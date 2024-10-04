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
elif [ -n "$1" ]; then
    # 입력 인자를 테스트 이름으로 취급
    selected_tests="$1"
    # 테스트가 mlfqs_tests에 있는지 확인하여 test_prefix 결정
    if contains "$mlfqs_tests" "$1"; then
        test_prefix="threads/mlfqs"
    elif contains "$args_tests" "$1"; then
        test_prefix="userprog"
    else
        test_prefix="threads"
    fi
else
    echo "Usage: $0 {alarm|priority|mlfqs|args|test_name}"
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
    elif contains "$args_tests" "$test"; then
        args=$(get_args "$test")
        echo "Running test $count of $total (ARGS): $test with args: $args"
        pintos -v -k -T 60 -m 20 --fs-disk=10 -p "tests/userprog/$test:$test" -- -q -f run "$test $args" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
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
    if contains "$args_tests" "$test"; then
        perl -I../.. "../../tests/$test_prefix/$test.ck" "tests/$test_prefix/$test" "tests/$test_prefix/$test.result"
    else
        perl -I../.. "../../tests/$test_prefix/$test.ck" "tests/$test_prefix/$test" "tests/$test_prefix/$test.result"
    fi
    count=$((count + 1))
done
