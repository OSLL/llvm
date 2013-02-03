type mem	= { base : string; index : string; scale : int; offset : int };;
type rawop	= Reg of string | Imm of int | Mem of mem;; 
type inst	= { name : string; ops : rawop array option };;
type symbol	= { name : string; insts : inst array };;

external disassemble : string -> symbol array = "caml_disassemble"
