#!/bin/bash

# 테스트할 디렉토리 및 파일 생성
mkdir -p test_dir

touch test_dir/file1.txt
touch test_dir/file2.log
touch test_dir/file3.data

echo "This is a test file 1." > test_dir/file1.txt
echo "This is a test file 2." > test_dir/file2.log
echo "This is a test file 3." > test_dir/file3.data

echo "Test directory and files created in 'test_dir'."

# C 프로그램 컴파일
gcc -o test_scene test_scene.c

if [ $? -eq 0 ]; then
    echo "Compilation successful. Executing the program..."
    
    # 프로그램 실행
    strace -o log.txt ./test_scene test_dir

    echo "Program executed."
else
    echo "Compilation failed."
fi
