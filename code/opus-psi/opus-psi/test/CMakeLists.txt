
set(TEST_SRCS
  test_psi_opus_client.cpp
  test_psi_opus_server.cpp
  )

foreach (filename ${TEST_SRCS})
  get_filename_component(testname ${filename} NAME_WE)
  add_executable(${testname} ${filename})
  target_link_libraries(${testname} opus-psi pthread)
endforeach ()

