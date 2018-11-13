#include <check.h>
#include "../src/line.h"

START_TEST(test_line_init)
{
	struct line line;
	irc_line_init(&line);
	irc_line_append(&line, "line");
	char *hi_string = irc_line_to_string(&line);
	ck_assert_str_eq(hi_string, "line\r\n");
	free(hi_string);
	_irc_line_deinit(&line);

	struct line *line2 = irc_line_new();
	irc_line_append(line2, "line");
	hi_string = irc_line_to_string(line2);
	ck_assert_str_eq(hi_string, "line\r\n");
	free(hi_string);
	irc_line_free(line2);
}
END_TEST

START_TEST(test_line_parse)
{
	struct line *line = irc_line_new_from_string(
		":origin COMMAND parameter1 parameter2 "
		":multi word parameter\r\n");
	ck_assert_int_eq(irc_line_count(line), 4);
	ck_assert(irc_line_includes(line, 0));
	ck_assert(irc_line_includes(line, 3));
	ck_assert(!irc_line_includes(line, 4));
	ck_assert_str_eq(line->origin, "origin");
	ck_assert_str_eq(irc_line_elem(line, 0), "COMMAND");
	ck_assert_str_eq(irc_line_elem(line, 1), "parameter1");
	ck_assert_str_eq(irc_line_elem(line, 2), "parameter2");
	ck_assert_str_eq(irc_line_elem(line, 3), "multi word parameter\r\n");
	irc_line_free(line);

	line = irc_line_new_from_string(
		"COMMAND parameter1 parameter2 :multi word parameter\r\n");
	ck_assert_int_eq(irc_line_count(line), 4);
	ck_assert(irc_line_includes(line, 0));
	ck_assert(irc_line_includes(line, 3));
	ck_assert(!irc_line_includes(line, 4));
	ck_assert_str_eq(irc_line_elem(line, 0), "COMMAND");
	ck_assert_str_eq(irc_line_elem(line, 1), "parameter1");
	ck_assert_str_eq(irc_line_elem(line, 2), "parameter2");
	ck_assert_str_eq(irc_line_elem(line, 3), "multi word parameter\r\n");
	irc_line_free(line);

	line = irc_line_new_from_string(":origin COMMAND\r\n");
	ck_assert_str_eq(line->origin, "origin");
	ck_assert_int_eq(irc_line_count(line), 1);
	ck_assert(irc_line_includes(line, 0));
	ck_assert(!irc_line_includes(line, 1));
	ck_assert_str_eq(irc_line_elem(line, 0), "COMMAND\r\n");
	irc_line_free(line);
}
END_TEST

START_TEST(test_elem_equals)
{
	struct line *line = irc_line_new_from_string(
		":origin COMMAND parameter1 parameter2 "
		":multi word parameter\r\n");
	ck_assert(irc_line_elem_equals(line, 0, "COMMAND"));
	ck_assert(irc_line_elem_case_equals(line, 0, "command"));
	ck_assert(!irc_line_elem_equals(line, 0, "notcommand"));
	ck_assert(!irc_line_elem_case_equals(line, 0, "notcommand"));
	irc_line_free(line);
}
END_TEST

START_TEST(test_line_pop)
{
	struct line *line = irc_line_new_from_string(
		":origin COMMAND parameter1 parameter2 "
		":multi word parameter\r\n");
	char *top = irc_line_pop(line);
	ck_assert_str_eq(top, "multi word parameter\r\n");
	free(top);
	top = irc_line_pop(line);
	ck_assert_str_eq(top, "parameter2");
	free(top);
	irc_line_free(line);
}
END_TEST

START_TEST(test_line_drop)
{
	struct line *line = irc_line_new_from_string(
		":origin COMMAND parameter1 parameter2 "
		":multi word parameter\r\n");
	irc_line_drop(line, 1);
	ck_assert(irc_line_elem_equals(line, 0, "COMMAND"));
	ck_assert(irc_line_elem_equals(line, 1, "parameter2"));
	irc_line_drop(line, 0);
	ck_assert(irc_line_elem_equals(line, 0, "parameter2"));
	irc_line_free(line);
}
END_TEST

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");

	tc_core = tcase_create("core");

	tcase_add_test(tc_core, test_line_init);
	tcase_add_test(tc_core, test_line_parse);
	tcase_add_test(tc_core, test_elem_equals);
	tcase_add_test(tc_core, test_line_pop);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = money_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
