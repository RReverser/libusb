typedef struct _MockingFixture MockingFixture;

MockingFixture* test_fixture_setup_mocking(void);
void test_fixture_add_canon(MockingFixture * fixture);
void test_fixture_teardown_mocking(MockingFixture * fixture);
