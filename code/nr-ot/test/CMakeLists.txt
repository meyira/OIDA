set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)

macro (add_test _name)
  add_compile_options("-Wall;-march=native;-O3;-funroll-loops;-maes;-mrdseed;-std=c++17;-fno-omit-frame-pointer")

	add_executable(${_name} "${_name}.cpp")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../CSI-FiSh)
  target_link_libraries(${_name} pq-ot keccak CSI-FiSh crypto ) 
endmacro()

add_test(test_oprf_nrot_server)
add_test(test_oprf_nrot_client)
add_test(test_psi_nrot_client)
add_test(test_psi_nrot_server)
add_test(test_prf_opt)
