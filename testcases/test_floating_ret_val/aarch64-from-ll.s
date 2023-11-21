	.text
	.file	"test_func_no_libc.c"
	.globl	func_1                          // -- Begin function func_1
	.p2align	2
	.type	func_1,@function
func_1:                                 // @func_1
	.cfi_startproc
// %bb.0:
	sub	sp, sp, #32
	.cfi_def_cfa_offset 32
	stp	x29, x30, [sp, #16]             // 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	stur	w0, [x29, #-4]
	str	w1, [sp, #8]
	ldur	w0, [x29, #-4]
	ldr	w1, [sp, #8]
	bl	__divsf3
	str	w0, [sp, #4]
	ldr	w0, [sp, #4]
	mov	w1, #1065353216                 // =0x3f800000
	bl	__addsf3
	str	w0, [sp, #4]
	ldr	w0, [sp, #4]
	.cfi_def_cfa wsp, 32
	ldp	x29, x30, [sp, #16]             // 16-byte Folded Reload
	add	sp, sp, #32
	.cfi_def_cfa_offset 0
	.cfi_restore w30
	.cfi_restore w29
	ret
.Lfunc_end0:
	.size	func_1, .Lfunc_end0-func_1
	.cfi_endproc
                                        // -- End function
	.ident	"clang version 17.0.5 (https://github.com/llvm/llvm-project 98bfdac5ce82d1679f8af9a57501471812ab68d7)"
	.section	".note.GNU-stack","",@progbits
