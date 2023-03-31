
add_executable(my_psi my_psi.cpp common/psi.cpp common/WaksmanPermutation.cpp)
target_link_libraries(my_psi ABY::aby ENCRYPTO_utils::encrypto_utils)
