"""
Tests for the functionality and infrastructure of grades tasks.
"""

from collections import OrderedDict
from contextlib import contextmanager
import ddt
from django.conf import settings
from django.db.utils import IntegrityError
from mock import patch
from unittest import skip

from student.models import anonymous_id_for_user
from student.tests.factories import UserFactory
from track.event_transaction_utils import (
    create_new_event_transaction_id,
    get_event_transaction_id,
)
from xmodule.modulestore.django import modulestore
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory, check_mongo_calls

from lms.djangoapps.grades.config.models import PersistentGradesEnabledFlag
from lms.djangoapps.grades.signals.signals import PROBLEM_WEIGHTED_SCORE_CHANGED
from lms.djangoapps.grades.tasks import recalculate_subsection_grade


@patch.dict(settings.FEATURES, {'PERSISTENT_GRADES_ENABLED_FOR_ALL_TESTS': False})
@ddt.ddt
class RecalculateSubsectionGradeTest(ModuleStoreTestCase):
    """
    Ensures that the recalculate subsection grade task functions as expected when run.
    """
    def setUp(self):
        super(RecalculateSubsectionGradeTest, self).setUp()
        self.user = UserFactory()
        PersistentGradesEnabledFlag.objects.create(enabled_for_all_courses=True, enabled=True)

    def set_up_course(self, enable_subsection_grades=True):
        """
        Configures the course for this test.
        """
        # pylint: disable=attribute-defined-outside-init,no-member
        self.course = CourseFactory.create(
            org='edx',
            name='course',
            run='run',
        )
        if not enable_subsection_grades:
            PersistentGradesEnabledFlag.objects.create(enabled=False)

        self.chapter = ItemFactory.create(parent=self.course, category="chapter", display_name="Chapter")
        self.sequential = ItemFactory.create(parent=self.chapter, category='sequential', display_name="Sequential1")
        self.problem = ItemFactory.create(parent=self.sequential, category='problem', display_name='Problem')

        self.problem_weighted_score_changed_kwargs = OrderedDict([
            ('weighted_earned', 1.0),
            ('weighted_possible', 2.0),
            ('user_id', self.user.id),
            ('course_id', unicode(self.course.id)),
            ('usage_id', unicode(self.problem.location)),
            ('only_if_higher', None),
        ])

        create_new_event_transaction_id()

        self.recalculate_subsection_grade_kwargs = OrderedDict([
            ('user_id', self.user.id),
            ('course_id', unicode(self.course.id)),
            ('usage_id', unicode(self.problem.location)),
            ('only_if_higher', None),
            ('weighted_earned', 1.0),
            ('weighted_possible', 2.0),
            ('score_deleted', False),
            ('event_transaction_id', unicode(get_event_transaction_id())),
            ('event_transaction_type', u'edx.grades.problem.submitted'),
        ])

        # this call caches the anonymous id on the user object, saving 4 queries in all happy path tests
        _ = anonymous_id_for_user(self.user, self.course.id)
        # pylint: enable=attribute-defined-outside-init,no-member

    def test_problem_weighted_score_changed_queues_task(self):
        """
        Ensures that the PROBLEM_WEIGHTED_SCORE_CHANGED signal enqueues the correct task.
        """
        self.set_up_course()
        send_args = self.problem_weighted_score_changed_kwargs
        local_task_args = self.recalculate_subsection_grade_kwargs.copy()
        local_task_args['event_transaction_type'] = u'edx.grades.problem.submitted'
        with patch(
            'lms.djangoapps.grades.tasks.recalculate_subsection_grade.apply_async',
            return_value=None
        ) as mock_task_apply:
            PROBLEM_WEIGHTED_SCORE_CHANGED.send(sender=None, **send_args)
            mock_task_apply.assert_called_once_with(kwargs=local_task_args)

    @patch('lms.djangoapps.grades.signals.signals.SUBSECTION_SCORE_CHANGED.send')
    def test_subsection_update_triggers_signal(self, mock_subsection_signal):
        """
        Ensures that the subsection update operation triggers a signal.
        """
        self.set_up_course()
        self._apply_recalculate_subsection_grade()
        self.assertTrue(mock_subsection_signal.called)

    @ddt.data(
        (ModuleStoreEnum.Type.mongo, 1),
        (ModuleStoreEnum.Type.split, 0),
    )
    @ddt.unpack
    def test_subsection_grade_updated(self, default_store, added_queries):
        with self.store.default_store(default_store):
            self.set_up_course()
            self.assertTrue(PersistentGradesEnabledFlag.feature_enabled(self.course.id))
            with check_mongo_calls(2) and self.assertNumQueries(22 + added_queries):
                self._apply_recalculate_subsection_grade()

    @patch('lms.djangoapps.grades.signals.signals.SUBSECTION_SCORE_CHANGED.send')
    def test_other_inaccessible_subsection(self, mock_subsection_signal):
        self.set_up_course()
        accessible_seq = ItemFactory.create(parent=self.chapter, category='sequential')
        inaccessible_seq = ItemFactory.create(parent=self.chapter, category='sequential', visible_to_staff_only=True)

        # Update problem to have 2 additional sequential parents.
        # So in total, 3 sequential parents, with one inaccessible.
        for sequential in (accessible_seq, inaccessible_seq):
            sequential.children = [self.problem.location]
            modulestore().update_item(sequential, self.user.id)  # pylint: disable=no-member

        # Make sure the signal is sent for only the 2 accessible sequentials.
        self._apply_recalculate_subsection_grade()
        self.assertEquals(mock_subsection_signal.call_count, 2)
        sequentials_signalled = {
            args[1]['subsection_grade'].location
            for args in mock_subsection_signal.call_args_list
        }
        self.assertSetEqual(
            sequentials_signalled,
            {self.sequential.location, accessible_seq.location},
        )

    def test_single_call_to_create_block_structure(self):
        self.set_up_course()
        self.assertTrue(PersistentGradesEnabledFlag.feature_enabled(self.course.id))
        with patch(
            'openedx.core.lib.block_structure.factory.BlockStructureFactory.create_from_cache',
            return_value=None,
        ) as mock_block_structure_create:
            self._apply_recalculate_subsection_grade()
            self.assertEquals(mock_block_structure_create.call_count, 1)

    @ddt.data(
        (ModuleStoreEnum.Type.mongo, 1),
        (ModuleStoreEnum.Type.split, 0),
    )
    @ddt.unpack
    def test_query_count_does_not_change_with_more_problems(self, default_store, added_queries):
        with self.store.default_store(default_store):
            self.set_up_course()
            self.assertTrue(PersistentGradesEnabledFlag.feature_enabled(self.course.id))
            ItemFactory.create(parent=self.sequential, category='problem', display_name='problem2')
            ItemFactory.create(parent=self.sequential, category='problem', display_name='problem3')
            with check_mongo_calls(2) and self.assertNumQueries(22 + added_queries):
                self._apply_recalculate_subsection_grade()

    @ddt.data(ModuleStoreEnum.Type.mongo, ModuleStoreEnum.Type.split)
    def test_subsection_grades_not_enabled_on_course(self, default_store):
        with self.store.default_store(default_store):
            self.set_up_course(enable_subsection_grades=False)
            self.assertFalse(PersistentGradesEnabledFlag.feature_enabled(self.course.id))
            with check_mongo_calls(2) and self.assertNumQueries(0):
                self._apply_recalculate_subsection_grade()

    @skip("Pending completion of TNL-5089")
    @ddt.data(
        (ModuleStoreEnum.Type.mongo, True),
        (ModuleStoreEnum.Type.split, True),
        (ModuleStoreEnum.Type.mongo, False),
        (ModuleStoreEnum.Type.split, False),
    )
    @ddt.unpack
    def test_query_counts_with_feature_flag(self, default_store, feature_flag):
        PersistentGradesEnabledFlag.objects.create(enabled=feature_flag)
        with self.store.default_store(default_store):
            self.set_up_course()
            with check_mongo_calls(0) and self.assertNumQueries(3 if feature_flag else 2):
                recalculate_subsection_grade.apply(kwargs=self.recalculate_subsection_grade_kwargs)

    @patch('lms.djangoapps.grades.tasks.recalculate_subsection_grade.retry')
    @patch('lms.djangoapps.grades.new.subsection_grade.SubsectionGradeFactory.update')
    def test_retry_subsection_update_on_integrity_error(self, mock_update, mock_retry):
        """
        Ensures that tasks will be retried if IntegrityErrors are encountered.
        """
        self.set_up_course()
        mock_update.side_effect = IntegrityError("WHAMMY")
        self._apply_recalculate_subsection_grade()
        self._assert_retry_called(mock_retry)

    @skip  # Pending completion of TNL-5995
    @patch('lms.djangoapps.grades.tasks.recalculate_subsection_grade.retry')
    def test_retry_subsection_grade_on_update_not_complete(self, mock_retry):
        self.set_up_course()
        self._apply_recalculate_subsection_grade()
        self._assert_retry_called(mock_retry)

    @skip  # Pending completion of TNL-5995
    @patch('lms.djangoapps.grades.tasks.recalculate_subsection_grade.retry')
    def test_retry_subsection_grade_on_no_score(self, mock_retry):
        self.set_up_course()
        self._apply_recalculate_subsection_grade()
        self._assert_retry_called(mock_retry)

    @patch('lms.djangoapps.grades.signals.signals.SUBSECTION_SCORE_CHANGED.send')
    @patch('lms.djangoapps.grades.new.subsection_grade.SubsectionGradeFactory.update')
    def test_retry_first_time_only(self, mock_update, mock_course_signal):
        """
        Ensures that a task retry completes after a one-time failure.
        """
        self.set_up_course()
        mock_update.side_effect = [IntegrityError("WHAMMY"), None]
        self._apply_recalculate_subsection_grade()
        self.assertEquals(mock_course_signal.call_count, 1)

    def _apply_recalculate_subsection_grade(self):
        """
        Calls the recalculate_subsection_grade task with necessary
        mocking in place.
        """
        recalculate_subsection_grade.apply(kwargs=self.recalculate_subsection_grade_kwargs)

    def _assert_retry_called(self, mock_retry):
        """
        Verifies the task was retried and with the correct
        number of arguments.
        """
        self.assertTrue(mock_retry.called)
        self.assertEquals(len(mock_retry.call_args[1]['kwargs']), len(self.recalculate_subsection_grade_kwargs))
