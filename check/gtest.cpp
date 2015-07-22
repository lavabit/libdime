#include "gtest/gtest.h"
#include "tap.h"

GTEST_API_ int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::TestEventListeners& listeners = testing::UnitTest::GetInstance()->listeners();

  // Delete the default listener
  delete listeners.Release(listeners.default_result_printer());
  listeners.Append(new tap::TapListener());
  return RUN_ALL_TESTS();
}
