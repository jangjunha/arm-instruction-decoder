import collections
import dataclasses
import enum
from typing import NamedTuple, Iterable, Union

from typeguard import typechecked


@typechecked
class DPInst(NamedTuple):
    Cond: str
    I: bool
    Opcode: str
    S: bool
    Rn: int
    Rd: int
    Operand2: str


@typechecked
class SDTInst(NamedTuple):
    Cond: str
    I: bool
    P: bool
    U: bool
    B: bool
    W: bool
    L: bool
    Rn: int
    Rd: int
    Offset: str


@typechecked
class BInst(NamedTuple):
    Cond: str
    L: bool
    Offset: int


Inst = Union[
    DPInst,
    SDTInst,
    BInst,
]


def bin_to_int(binary: str, signed: bool) -> int:
    if signed:
        if binary[0] == "0":
            return int(binary, 2)
        else:
            bitflipped = "".join(str(1 - int(b)) for b in binary)
            return -(int(bitflipped, 2) + 1)
    else:
        return int(binary, 2)


@typechecked
@dataclasses.dataclass
class Instruction:
    offset: str
    content: str

    @staticmethod
    def parse(string: str) -> "Instruction":
        d = string.split()
        return Instruction(
            offset=d[0],
            content=int(d[2].rstrip(";"), 16),
        )

    @property
    def bin(self) -> str:
        return f"{self.content:032b}"

    @property
    def hex(self) -> str:
        return hex(self.content)

    @property
    def bin_spaced(self):
        return " ".join(
            [
                self.bin[0:4],
                self.bin[4:6],
                self.bin[6:7],
                self.bin[7:11],
                self.bin[11],
                self.bin[12:16],
                self.bin[16:20],
                self.bin[20:24],
                self.bin[24:28],
                self.bin[28:32],
            ]
        )

    @property
    def inst(self) -> Inst:
        # Data Processing
        if self.bin[4:6] == "00":
            return DPInst(
                Cond=self.bin[0:4],
                I=self.bin[6] == "1",
                Opcode=self.bin[7:11],
                S=self.bin[11] == "1",
                Rn=bin_to_int(self.bin[12:16], signed=False),
                Rd=bin_to_int(self.bin[16:20], signed=False),
                Operand2=self.bin[20:32],
            )

        # Single Data Transfer
        elif self.bin[4:6] == "01":
            return SDTInst(
                Cond=self.bin[0:4],
                I=self.bin[6] == "1",
                P=self.bin[7] == "1",
                U=self.bin[8] == "1",
                B=self.bin[9] == "1",
                W=self.bin[10] == "1",
                L=self.bin[11] == "1",
                Rn=bin_to_int(self.bin[12:16], signed=False),
                Rd=bin_to_int(self.bin[16:20], signed=False),
                Offset=self.bin[20:32],
            )

        # Branch
        elif self.bin[4:7] == "101":
            return BInst(
                Cond=self.bin[0:4],
                L=self.bin[7] == "1",
                Offset=bin_to_int(self.bin[8:32], signed=True),
            )

        else:
            raise NotImplementedError(
                f'category() for "{self.bin_spaced}" not implemented.'
            )

    @property
    def cond(self):
        CONDS = {
            "0000": "EQ",
            "0001": "NE",
            "1110": "",
        }
        return CONDS[self.bin[0:4]]

    def __str__(self) -> str:
        inst = self.inst
        operands = []
        comments = []

        if isinstance(inst, DPInst):
            if inst.Opcode == "0010":
                operation = "SUB"
                operand_fmt = "{Rd} := {Op1} - {Op2}"
            elif inst.Opcode == "0100":
                operation = "ADD"
                operand_fmt = "{Rd} := {Op1} + {Op2}"
            elif inst.Opcode == "1010":
                operation = "CMP"
                operand_fmt = "set condition codes on {Op1} - {Op2}"
            elif inst.Opcode == "1101":
                operation = "MOV"
                operand_fmt = "{Rd} := {Op2}"
            else:
                raise NotImplementedError(
                    f"Cannot process opcode {inst.Opcode}; {self.offset}: {self.bin_spaced}"
                )

            comments.append(
                "set condition codes" if inst.S else "do not alter condition codes"
            )

            if inst.I:
                rotate = bin_to_int(inst.Operand2[:4], signed=False)
                imm = bin_to_int(inst.Operand2[4:], signed=False)
                operands.append(
                    operand_fmt.format(
                        Rd=f"${inst.Rd}",
                        Op1=f"${inst.Rn}",
                        Op2=f"sign-ext(#{imm:#x} << {rotate})",
                    )
                )
            else:
                Rm = bin_to_int(inst.Operand2[8:], signed=False)
                shtype = inst.Operand2[5:7]
                shop = {
                    "00": "logical-left-shift",
                    "01": "logical-right-shift",
                    "10": "arithmetic-right-shift",
                    "11": "rotate-right-shift",
                }[shtype]
                if inst.Operand2[7] == "0":
                    shamt = bin_to_int(inst.Operand2[0:5], signed=False)
                    assert shamt == 0
                    operands.append(
                        operand_fmt.format(
                            Rd=f"${inst.Rd}",
                            Op1=f"${inst.Rn}",
                            Op2=f"{shop}(${Rm}, #{shamt:#x})",
                        )
                    )
                elif inst.Operand2[7] == "1" and inst.Operand2[4] == "0":
                    shreg = bin_to_int(inst.Operand2[0:4], signed=False)
                    operands.append(
                        operand_fmt.format(
                            Rd=f"${inst.Rd}",
                            Op1=f"${inst.Rn}",
                            Op2=f"{shop}(${Rm}, ${shreg})",
                        )
                    )
                else:
                    raise NotImplementedError("Unexpected error. 6341895")

        elif isinstance(inst, SDTInst):
            assert inst.P is True  # Pre; add offset before transfer
            assert inst.U is True  # Up; add offset to base
            assert inst.B is False  # Byte quantity
            assert inst.W is False  # No write-back
            comments.append("pre/up/byte/no-wb")

            if inst.L:
                operation = "LDR"
            else:
                operation = "STR"

            operands.append(
                f"${inst.Rd}",
            )

            if inst.I:
                raise NotImplementedError(
                    f"SDTInst I=1 not implemented. {self.offset}: {self.bin_spaced}"
                )
            else:
                imm_offset = bin_to_int(inst.Offset, signed=False)
                operands.append(
                    f"[${inst.Rn} + #{imm_offset:#x}]",
                )

        elif isinstance(inst, BInst):
            operation = "BL" if inst.L else "B"
            operands.append(
                f"#{inst.Offset:#x}",
            )

        else:
            raise NotImplementedError(
                f'__str__() for "{self.bin_spaced}" not implemented.'
            )

        operation = operation + self.cond

        comment = ("  # " + ", ".join(comments)) if comments else ""
        return "{operation}\t{operands}{comment}".format(
            operation=operation,
            operands=", ".join(operands),
            comment=comment,
        )


@typechecked
def read_mif(filename: str) -> Iterable[Instruction]:
    with open(filename) as f:
        begin = False
        for _line in f:
            line = _line.strip()

            if line == "CONTENT BEGIN":
                begin = True
                continue
            elif line == "END;":
                break

            if not begin:
                continue

            yield Instruction.parse(line)


if __name__ == "__main__":
    for instruction in read_mif("sample.mif"):
        prefix = f"{instruction.offset:10s}:"
        try:
            asm = str(instruction)
            print(f"{prefix}: {asm}")
        except Exception as e:
            print(f"{prefix}: ! ${instruction.bin_spaced}")
