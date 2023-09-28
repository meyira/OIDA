add_library(pq-ot SHARED
    pq-ot.cpp
    pq-otmain.cpp
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
target_link_libraries(pq-ot
    PUBLIC
    SEAL::seal
    emp-tool
)
