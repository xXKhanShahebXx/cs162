# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(write-coalesce) begin
(write-coalesce) Resetting buffer cache
(write-coalesce) Initial stats: 249 reads, 969 writes
(write-coalesce) create test file
(write-coalesce) open test file
(write-coalesce) Writing 64 KB file in 512-byte chunks
(write-coalesce) write chunk 0
(write-coalesce) write chunk 1
(write-coalesce) write chunk 2
(write-coalesce) write chunk 3
(write-coalesce) write chunk 4
(write-coalesce) write chunk 5
(write-coalesce) write chunk 6
(write-coalesce) write chunk 7
(write-coalesce) write chunk 8
(write-coalesce) write chunk 9
(write-coalesce) write chunk 10
(write-coalesce) write chunk 11
(write-coalesce) write chunk 12
(write-coalesce) write chunk 13
(write-coalesce) write chunk 14
(write-coalesce) write chunk 15
(write-coalesce) write chunk 16
(write-coalesce) write chunk 17
(write-coalesce) write chunk 18
(write-coalesce) write chunk 19
(write-coalesce) write chunk 20
(write-coalesce) write chunk 21
(write-coalesce) write chunk 22
(write-coalesce) write chunk 23
(write-coalesce) write chunk 24
(write-coalesce) write chunk 25
(write-coalesce) write chunk 26
(write-coalesce) write chunk 27
(write-coalesce) write chunk 28
(write-coalesce) write chunk 29
(write-coalesce) write chunk 30
(write-coalesce) write chunk 31
(write-coalesce) write chunk 32
(write-coalesce) Written 16 KB so far...
(write-coalesce) write chunk 33
(write-coalesce) write chunk 34
(write-coalesce) write chunk 35
(write-coalesce) write chunk 36
(write-coalesce) write chunk 37
(write-coalesce) write chunk 38
(write-coalesce) write chunk 39
(write-coalesce) write chunk 40
(write-coalesce) write chunk 41
(write-coalesce) write chunk 42
(write-coalesce) write chunk 43
(write-coalesce) write chunk 44
(write-coalesce) write chunk 45
(write-coalesce) write chunk 46
(write-coalesce) write chunk 47
(write-coalesce) write chunk 48
(write-coalesce) write chunk 49
(write-coalesce) write chunk 50
(write-coalesce) write chunk 51
(write-coalesce) write chunk 52
(write-coalesce) write chunk 53
(write-coalesce) write chunk 54
(write-coalesce) write chunk 55
(write-coalesce) write chunk 56
(write-coalesce) write chunk 57
(write-coalesce) write chunk 58
(write-coalesce) write chunk 59
(write-coalesce) write chunk 60
(write-coalesce) write chunk 61
(write-coalesce) write chunk 62
(write-coalesce) write chunk 63
(write-coalesce) write chunk 64
(write-coalesce) Written 32 KB so far...
(write-coalesce) write chunk 65
(write-coalesce) write chunk 66
(write-coalesce) write chunk 67
(write-coalesce) write chunk 68
(write-coalesce) write chunk 69
(write-coalesce) write chunk 70
(write-coalesce) write chunk 71
(write-coalesce) write chunk 72
(write-coalesce) write chunk 73
(write-coalesce) write chunk 74
(write-coalesce) write chunk 75
(write-coalesce) write chunk 76
(write-coalesce) write chunk 77
(write-coalesce) write chunk 78
(write-coalesce) write chunk 79
(write-coalesce) write chunk 80
(write-coalesce) write chunk 81
(write-coalesce) write chunk 82
(write-coalesce) write chunk 83
(write-coalesce) write chunk 84
(write-coalesce) write chunk 85
(write-coalesce) write chunk 86
(write-coalesce) write chunk 87
(write-coalesce) write chunk 88
(write-coalesce) write chunk 89
(write-coalesce) write chunk 90
(write-coalesce) write chunk 91
(write-coalesce) write chunk 92
(write-coalesce) write chunk 93
(write-coalesce) write chunk 94
(write-coalesce) write chunk 95
(write-coalesce) write chunk 96
(write-coalesce) Written 48 KB so far...
(write-coalesce) write chunk 97
(write-coalesce) write chunk 98
(write-coalesce) write chunk 99
(write-coalesce) write chunk 100
(write-coalesce) write chunk 101
(write-coalesce) write chunk 102
(write-coalesce) write chunk 103
(write-coalesce) write chunk 104
(write-coalesce) write chunk 105
(write-coalesce) write chunk 106
(write-coalesce) write chunk 107
(write-coalesce) write chunk 108
(write-coalesce) write chunk 109
(write-coalesce) write chunk 110
(write-coalesce) write chunk 111
(write-coalesce) write chunk 112
(write-coalesce) write chunk 113
(write-coalesce) write chunk 114
(write-coalesce) write chunk 115
(write-coalesce) write chunk 116
(write-coalesce) write chunk 117
(write-coalesce) write chunk 118
(write-coalesce) write chunk 119
(write-coalesce) write chunk 120
(write-coalesce) write chunk 121
(write-coalesce) write chunk 122
(write-coalesce) write chunk 123
(write-coalesce) write chunk 124
(write-coalesce) write chunk 125
(write-coalesce) write chunk 126
(write-coalesce) write chunk 127
(write-coalesce) Device writes: 523 for 64 KB file (128 sectors)
(write-coalesce) PASS: Write count is reasonable
(write-coalesce) Verifying file contents
(write-coalesce) reopen file
(write-coalesce) Verified 16 KB so far...
(write-coalesce) Verified 32 KB so far...
(write-coalesce) Verified 48 KB so far...
(write-coalesce) file contents are correct
(write-coalesce) remove file
(write-coalesce) end
EOF
pass;