#!/bin/sh

# 테스트 목록
alarm_tests=" \
alarm-single \
alarm-multiple \
alarm-simultaneous \
alarm-priority \
alarm-zero \
alarm-negative \
"

priority_tests=" \
priority-change \
priority-condvar \
priority-fifo \
priority-preempt \
priority-sema \
priority-donate-chain \
priority-donate-lower \
priority-donate-multiple \
priority-donate-multiple2 \
priority-donate-nest \
priority-donate-one \
priority-donate-sema \
"

mlfqs_tests=" \
mlfqs-load-1 \
mlfqs-load-60 \
mlfqs-load-avg \
mlfqs-recent-1 \
mlfqs-fair-2 \
mlfqs-fair-20 \
mlfqs-nice-2 \
mlfqs-nice-10 \
mlfqs-block \
"

args_tests=" \
args-none \
args-single \
args-multiple \
args-many \
args-dbl-space \
"

bad_tests=" \
bad-jump \
bad-jump2 \
bad-read \
bad-read2 \
bad-write \
bad-write2 \
"

write_tests=" \
write-normal \
write-bad-ptr \
write-boundary \
write-zero \
write-stdin \
write-bad-fd \
"

open_tests=" \
open-normal \
open-missing \
open-boundary \
open-empty \
open-null \
open-bad-ptr \
open-twice \
"

create_tests=" \
create-normal \
create-empty \
create-null \
create-bad-ptr \
create-long \
create-exists \
create-bound \
"

read_tests=" \
read-normal \
read-bad-ptr \
read-boundary \
read-zero \
read-stdout \
read-bad-fd \
"

exec_tests=" \
exec-once \
exec-arg \
exec-boundary \
exec-missing \
exec-bad-ptr \
exec-read \
"

fork_tests=" \
fork-once \
fork-multiple \
fork-recursive \
fork-read \
fork-close \
fork-boundary \
"

userprog_tests="$args_tests $bad_tests $write_tests $open_tests $create_tests $read_tests $exec_tests $fork_tests"

# 특정 테스트가 목록에 있는지 확인하는 함수
contains() {
    case " $1 " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

# args 테스트별로 전달할 인수를 반환하는 함수
get_args() {
    case "$1" in
        args-none)
            echo ""
            ;;
        args-single)
            echo "onearg"
            ;;
        args-multiple)
            echo "some arguments for you!"
            ;;
        args-many)
            echo "a b c d e f g h i j k l m n o p q r s t u v"
            ;;
        args-dbl-space)
            echo "two  spaces!"
            ;;
        *)
            echo ""
            ;;
    esac
}

get_pintos_options() {
    case "$1" in
        write-normal|write-bad-ptr|write-boundary|write-zero|open-normal|open-boundary|open-twice|read-normal|read-bad-ptr|read-boundary|read-zero|fork-read|fork-close)
            echo "-p ../../tests/userprog/sample.txt:sample.txt"
            ;;
        exec-once)
            echo "-p tests/userprog/child-simple:child-simple"
            ;;
        exec-arg)
            echo "-p tests/userprog/child-args:child-args"
            ;;
        exec-boundary)
            echo "-p tests/userprog/child-simple:child-simple"
            ;;
        exec-missing)
            echo ""
            ;;
        exec-bad-ptr)
            echo ""
            ;;
        exec-read)
            echo "-p ../../tests/userprog/sample.txt:sample.txt -p tests/userprog/child-read:child-read"
            ;;
        *)
            echo ""
            ;;
    esac
}

# 인자를 검사하여 실행할 테스트를 결정
if [ "$1" = "alarm" ]; then
    selected_tests="$alarm_tests"
    test_prefix="threads"
elif [ "$1" = "priority" ]; then
    selected_tests="$priority_tests"
    test_prefix="threads"
elif [ "$1" = "mlfqs" ]; then
    selected_tests="$mlfqs_tests"
    test_prefix="threads/mlfqs"
elif [ "$1" = "args" ]; then
    selected_tests="$args_tests"
    test_prefix="userprog"
elif [ "$1" = "bad" ]; then
    selected_tests="$bad_tests"
    test_prefix="userprog"
elif [ "$1" = "write" ]; then
    selected_tests="$write_tests"
    test_prefix="userprog"
elif [ "$1" = "open" ]; then
    selected_tests="$open_tests"
    test_prefix="userprog"
elif [ "$1" = "create" ]; then
    selected_tests="$create_tests"
    test_prefix="userprog"
elif [ "$1" = "read" ]; then
    selected_tests="$read_tests"
    test_prefix="userprog"
elif [ "$1" = "exec" ]; then
    selected_tests="$exec_tests"
    test_prefix="userprog"
elif [ "$1" = "fork" ]; then
    selected_tests="$fork_tests"
    test_prefix="userprog"
elif [ -n "$1" ]; then
    # 입력 인자를 테스트 이름으로 취급
    selected_tests="$1"
    # 테스트가 mlfqs_tests, userprog_tests에 있는지 확인하여 test_prefix 결정
    if contains "$mlfqs_tests" "$1"; then
        test_prefix="threads/mlfqs"
    elif contains "$userprog_tests" "$1"; then
        test_prefix="userprog"
    else
        test_prefix="threads"
    fi
else
    echo "Usage: $0 {alarm|priority|mlfqs|args|bad|write|open|create|read|exec|fork|test_name}"
    exit 1
fi

# 빌드 작업 수행
if [ "$test_prefix" = "userprog" ]; then
    cd userprog && make clean && make && cd build || exit
else
    cd threads && make clean && make && cd build || exit
fi

# Pintos 실행 및 진행 상황 출력
count=1
total=$(echo "$selected_tests" | wc -w)
for test in $selected_tests; do
    if contains "$mlfqs_tests" "$test"; then
        echo "Running test $count of $total (MLFQS): $test"
        pintos -v -k -T 480 -m 20 -- -q -mlfqs run "$test" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
    elif contains "$userprog_tests" "$test"; then
        args=$(get_args "$test")
        pintos_options=$(get_pintos_options "$test")
        if contains "$args_tests" "$test"; then
            echo "Running test $count of $total (ARGS): $test with args: $args"
        elif contains "$write_tests" "$test"; then
            echo "Running test $count of $total (WRITE): $test"
        elif contains "$open_tests" "$test"; then
            echo "Running test $count of $total (OPEN): $test"
        elif contains "$create_tests" "$test"; then
            echo "Running test $count of $total (CREATE): $test"
        elif contains "$read_tests" "$test"; then
            echo "Running test $count of $total (READ): $test"
        elif contains "$exec_tests" "$test"; then
            echo "Running test $count of $total (EXEC): $test"
        elif contains "$fork_tests" "$test"; then
            echo "Running test $count of $total (FORK): $test"
        else
            echo "Running test $count of $total (USERPROG): $test"
        fi
        if [ -z "$args" ]; then
            pintos -v -k -T 60 -m 20 --fs-disk=10 -p "tests/userprog/$test:$test" $pintos_options -- -q -f run "$test" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
        else
            pintos -v -k -T 60 -m 20 --fs-disk=10 -p "tests/userprog/$test:$test" $pintos_options -- -q -f run "$test $args" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
        fi
    else
        echo "Running test $count of $total: $test"
        pintos -v -k -T 60 -m 20 -- -q run "$test" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
    fi
    count=$((count + 1))
done

# Perl 체크 및 진행 상황 출력
count=1
for test in $selected_tests; do
    echo "Running Perl check $count of $total: $test"
    perl -I../.. "../../tests/$test_prefix/$test.ck" "tests/$test_prefix/$test" "tests/$test_prefix/$test.result"
    count=$((count + 1))
done
