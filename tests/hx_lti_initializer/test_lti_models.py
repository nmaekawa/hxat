import pytest


from hx_lti_initializer.models import LTICourse
from hx_lti_initializer.models import LTIProfile


@pytest.mark.django_db
def test_LTICourse_get_course_by_id(user_profile_factory):
    """
    Checks that you can get a course given an id.
    """
    # TODO: chack that is ok to add 'Learner' as admin to course
    instructor = user_profile_factory()
    course_object = LTICourse.create_course('test_course_id', instructor)
    course_to_test = LTICourse.get_course_by_id('test_course_id')

    assert(isinstance(course_to_test, LTICourse))
    assert(course_object == course_to_test)
    assert(course_to_test.course_id == 'test_course_id')


@pytest.mark.django_db
def test_LTICourse_get_courses_of_admin(user_profile_factory):
    """
    Checks that it returns a list of all the courses for that admin.
    """
    instructor = user_profile_factory(roles=['Instructor'])

    course_object = LTICourse.create_course('test_course_id', instructor)
    list_of_courses = LTICourse.get_courses_of_admin(instructor)
    assert(isinstance(list_of_courses, list))
    assert(len(list_of_courses) == 1)
    assert(course_object in list_of_courses)

    course_object2 = LTICourse.create_course('test_course_id2', instructor)
    list_of_courses2 = LTICourse.get_courses_of_admin(instructor)
    assert(len(list_of_courses2) == 2)
    assert(course_object2 in list_of_courses2)


@pytest.mark.django_db
def test_LTICourse_get_all_courses(user_profile_factory):
    """
    Checks that all courses are returned regardless of admin user
    """
    profile1 = user_profile_factory(roles=['Instructor'])
    profile2 = user_profile_factory()

    user1 = LTIProfile.objects.get(user_id=profile1.user.pk)
    user2 = LTIProfile.objects.get(user_id=profile2.user.pk)

    list_of_courses = LTICourse.get_all_courses()
    assert(isinstance(list_of_courses, list))
    assert(len(list_of_courses) == 0)

    LTICourse.create_course('test_course_id', user1)
    list_of_courses2 = LTICourse.get_all_courses()
    assert(isinstance(list_of_courses2, list))
    assert(len(list_of_courses2) == 1)

    LTICourse.create_course('test_course_id2', user2)
    list_of_courses3 = LTICourse.get_all_courses()
    assert(isinstance(list_of_courses3, list))
    assert(len(list_of_courses3) == 2)


