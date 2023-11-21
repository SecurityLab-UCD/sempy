	.text
	.file	"test_func_no_libc.c"
	.globl	func_1                          // -- Begin function func_1
	.p2align	2
	.type	func_1,@function
func_1:                                 // @func_1
	.cfi_startproc
// %bb.0:
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	s0, [sp, #12]
	str	s1, [sp, #8]
	ldr	s0, [sp, #12]
	ldr	s1, [sp, #8]
	fdiv	s0, s0, s1
	str	s0, [sp, #4]
	ldr	s0, [sp, #4]
	fmov	s1, #1.00000000
	fadd	s0, s0, s1
	str	s0, [sp, #4]
	ldr	s0, [sp, #4]
	add	sp, sp, #16
	.cfi_def_cfa_offset 0
	ret
.Lfunc_end0:
	.size	func_1, .Lfunc_end0-func_1
	.cfi_endproc
                                        // -- End function
	.ident	"clang version 17.0.5 (https://github.com/llvm/llvm-project 98bfdac5ce82d1679f8af9a57501471812ab68d7)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
