set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


macro (add_test _name)
  add_compile_options("-Wall;-march=native;-O3;-funroll-loops;-maes;-mrdseed;-std=c++17;-fno-omit-frame-pointer")

	add_executable(${_name} "${_name}.cpp")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../CSI-FiSh)
  target_link_libraries(${_name} pq-ot keccak CSI-FiSh crypto ) 
endmacro()

add_test(oprf_server)
add_test(oprf_client)
add_test(psi_client)
add_test(psi_server)
add_test(prf_opt)
