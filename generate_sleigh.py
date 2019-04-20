#!/usr/bin/env python3
'''
This script was written to help me generate SLEIGH code to disassemble an
architecture for which I had a objdump binary but no documentation.

Inside objdump is a table of assembler format strings with control codes (like
`%3-5r`) that describe how individual bits of the encoded instruction ought to
be interpreted.

By parsing these format strings, we can translate them into SLEIGH code.

Ryan Govostes
April 14, 2019
'''

import re

# These are extracted from the `thumb_opcodes` and `thumb_opcodes32` arrays
# from tc32-elf-objdump.exe, which was repurposed from the original code.
# 
# Each (value, mask, assembler) tuple tells the `print_insn_thumb16` function,
# also repurposed, how to decode an instruction.
#
# Note that bitfield ranges here are specified with bit 0 as the *last* bit of
# the encoded instruction.
insns = [
  (16, 0x46c0, 0xffff, 'tnop%c\\t\\t\\t; (mov r8, r8)'),
  (16, 0x0000, 0xffc0, 'tand%C\\t%0-2r, %3-5r'),
  (16, 0x0040, 0xffc0, 'txor%C\\t%0-2r, %3-5r'),
  (16, 0x0080, 0xffc0, 'tshftl%C\\t%0-2r, %3-5r'),
  (16, 0x00c0, 0xffc0, 'tshftr%C\\t%0-2r, %3-5r'),
  (16, 0x0100, 0xffc0, 'tasr%C\\t%0-2r, %3-5r'),
  (16, 0x0140, 0xffc0, 'taddc%C\\t%0-2r, %3-5r'),
  (16, 0x0180, 0xffc0, 'tsubc%C\\t%0-2r, %3-5r'),
  (16, 0x01c0, 0xffc0, 'trotr%C\\t%0-2r, %3-5r'),
  (16, 0x0200, 0xffc0, 'tnand%c\\t%0-2r, %3-5r'),
  (16, 0x0240, 0xffc0, 'tneg%C\\t%0-2r, %3-5r'),
  (16, 0x0280, 0xffc0, 'tcmp%c\\t%0-2r, %3-5r'),
  (16, 0x02c0, 0xffc0, 'tcmpn%c\\t%0-2r, %3-5r'),
  (16, 0x0300, 0xffc0, 'tor%C\\t%0-2r, %3-5r'),
  (16, 0x0340, 0xffc0, 'tmul%C\\t%0-2r, %3-5r'),
  (16, 0x0380, 0xffc0, 'tbclr%C\\t%0-2r, %3-5r'),
  (16, 0x03c0, 0xffc0, 'tmovn%C\\t%0-2r, %3-5r'),
  (16, 0x6bc0, 0xfff8, 'tmcsr%c\\t%0-2r'),
  (16, 0x6bc8, 0xfff8, 'tmrcs%c\\t%0-2r'),
  (16, 0x6bd0, 0xfff8, 'tmssr%c\\t%0-2r'),
  (16, 0x6bd8, 0xfff8, 'tmrss%c\\t%0-2r'),
  (16, 0x6800, 0xfe00, 'treti\\t%O'),
  (16, 0x6000, 0xff80, 'tadd%c\\tsp, #%0-6W'),
  (16, 0x6080, 0xff80, 'tsub%c\\tsp, #%0-6W'),
  (16, 0x0700, 0xff80, 'tjex%c\\t%S%x'),
  (16, 0x0400, 0xff00, 'tadd%c\\t%D, %S'),
  (16, 0x0500, 0xff00, 'tcmp%c\\t%D, %S'),
  (16, 0x0600, 0xff00, 'tmov%c\\t%D, %S'),
  (16, 0x6400, 0xfe00, 'tpush%c\\t%N'),
  (16, 0x6c00, 0xfe00, 'tpop%c\\t%O'),
  (16, 0xe800, 0xfe00, 'tadd%C\\t%0-2r, %3-5r, %6-8r'),
  (16, 0xea00, 0xfe00, 'tsub%C\\t%0-2r, %3-5r, %6-8r'),
  (16, 0xec00, 0xfe00, 'tadd%C\\t%0-2r, %3-5r, #%6-8d'),
  (16, 0xee00, 0xfe00, 'tsub%C\\t%0-2r, %3-5r, #%6-8d'),
  (16, 0x1200, 0xfe00, 'tstorerh%c\\t%0-2r, [%3-5r, %6-8r]'),
  (16, 0x1a00, 0xfe00, 'tloadrh%c\\t%0-2r, [%3-5r, %6-8r]'),
  (16, 0x1600, 0xf600, 'tloadrs%11?hb%c\\t%0-2r, [%3-5r, %6-8r]'),
  (16, 0x1000, 0xfa00, "tstorer%10'b%c\t%0-2r, [%3-5r, %6-8r]"),
  (16, 0x1800, 0xfa00, "tloadr%10'b%c\t%0-2r, [%3-5r, %6-8r]"),
  (16, 0xf000, 0xf800, 'tshftl%C\\t%0-2r, %3-5r, #%6-10d'),
  (16, 0xf800, 0xf800, 'tshftr%C\\t%0-2r, %3-5r, %s'),
  (16, 0xe000, 0xf800, 'tasr%C\\t%0-2r, %3-5r, %s'),
  (16, 0xa000, 0xf800, 'tmov%C\\t%8-10r, #%0-7d'),
  (16, 0xa800, 0xf800, 'tcmp%c\\t%8-10r, #%0-7d'),
  (16, 0xb000, 0xf800, 'tadd%C\\t%8-10r, #%0-7d'),
  (16, 0xb800, 0xf800, 'tsub%C\\t%8-10r, #%0-7d'),
  (16, 0x0800, 0xf800, 'tloadr%c\\t%8-10r, [pc, #%0-7W]\\t; (%0-7a)'),
  (16, 0x5000, 0xf800, 'tstorer%c\\t%0-2r, [%3-5r, #%6-10W]'),
  (16, 0x5800, 0xf800, 'tloadr%c\\t%0-2r, [%3-5r, #%6-10W]'),
  (16, 0x4000, 0xf800, 'tstorerb%c\\t%0-2r, [%3-5r, #%6-10d]'),
  (16, 0x4800, 0xf800, 'tloadrb%c\\t%0-2r, [%3-5r, #%6-10d]'),
  (16, 0x2000, 0xf800, 'tstorerh%c\\t%0-2r, [%3-5r, #%6-10H]'),
  (16, 0x2800, 0xf800, 'tloadrh%c\\t%0-2r, [%3-5r, #%6-10H]'),
  (16, 0x3000, 0xf800, 'tstorer%c\\t%8-10r, [sp, #%0-7W]'),
  (16, 0x3800, 0xf800, 'tloadr%c\\t%8-10r, [sp, #%0-7W]'),
  (16, 0x7000, 0xf800, 'tadd%c\\t%8-10r, pc, #%0-7W\\t; (t.add %8-10r, %0-7a)'),
  (16, 0x7800, 0xf800, 'tadd%c\\t%8-10r, sp, #%0-7W'),
  (16, 0xd000, 0xf800, 'tstorem%c\\t%8-10r!, %M'),
  (16, 0xd800, 0xf800, 'tloadm%c\\t%8-10r!, %M'),
  (16, 0xcf00, 0xff00, 'tserv%c\\t%0-7d'),
# (16, 0xce00, 0xfe00, 'undefined instruction %0-31x'),
  (16, 0xc000, 0xf000, 'tj%8-11c.n\\t%0-7B%X'),
  (16, 0x8000, 0xf800, 'tj%c.n\\t%0-10B%x'),
  (32, 0x9000c000, 0xf800d000, 'tjlex%c\\t%B%x'),
  (32, 0x90009800, 0xf800f800, 'tjl%c\\t%B%x'),
]


################################################################################

# ---- FIXME ----
# This is a terribly designed tree structure that explains how the fields and 
# registers and computed values are related. It needs to be redesigned.
# ---- FIXME ----

class Expression:
  def __init__(self):
    self.children = []
  
  def __eq__(self, rhs):
    return isinstance(rhs, type(self)) and repr(self) == repr(rhs)
  
  def __hash__(self):
    return hash(repr(self))
  
  def findall(self, predicate):
    found = set()
    explored = set([self])
    to_explore = list(self.children)
    if predicate(self):
      found.add(self)
    while len(to_explore) > 0:
      child = to_explore.pop()
      if child in explored:
        continue
      explored.add(child)
      if isinstance(child, Expression):
        to_explore.extend(child.children)
      if predicate(child):
        found.add(child)
    return found


class Field(Expression):
  '''
  A Field is a bitfield that is extracted from the encoded instruction.
  It is a leaf node of an expression tree.
  '''
  def __init__(self, purpose, lo, size, attributes=None):
    super().__init__()
    self.purpose, self.lo, self.size = purpose, lo, size
    self.attributes = attributes or []
  
  @property
  def name(self):
    return '%s_%i_%i' % (self.purpose, self.lo, self.size)
  
  @property
  def hi(self):
    return self.lo + self.size - 1
  
  def as_sleigh_definition(self):
    return '%s = (%i, %i)%s' % (self.name, self.lo, self.hi,
      (' %s' % ' '.join(self.attributes) if self.attributes else ''))
  
  def __repr__(self):
    return 'Field(%r, %r, %r)' % (self.purpose, self.lo, self.size)


class Register(Expression):
  '''
  A Register is a reference to a specific register's value, such as $r3. It
  is a leaf node of an expression tree.
  '''
  def __init__(self, name):
    super().__init__()
    self.name = name
  
  def __repr__(self):
    return 'Register(%r)' % (self.name)


class ContextVariable(Expression):
  '''
  A ContextVariable is a bitfield that extracted from a specific register.
  '''
  def __init__(self, name, register, lo, size, attributes=None):
    super().__init__()
    self.name, self.register, self.lo, self.size = name, register, lo, size
    self.attributes = attributes or []
    self.children.append(self.register)
  
  @property
  def hi(self):
    return self.lo + self.size - 1
  
  def as_sleigh_definition(self):
    return '%s = (%i, %i)%s' % (self.name, self.lo, self.hi,
      (' %s' % ' '.join(self.attributes) if self.attributes else ''))
  
  def __repr__(self):
    return 'ContextVariable(%r, %r, %r, %r)' \
      % (self.name, self.register, self.lo, self.size)


class ComputedValue(Expression):
  def __init__(self, name, children):
    super().__init__()
    self.name = name
    self.children = children
  
  def __repr__(self):
    return 'ComputedValue(%r, children=%r)' \
      % (self.name, self.children)


################################################################################


# Here are the format control codes that are supported. Most are assumed to be
# based on the original `print_insn_thumb16` code, unless otherwise noted.
#
# See:
# http://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=opcodes/arm-dis.c;hb=HEAD#l2508

class ControlCode:
  def expand(self):
    '''
    This must return an element or iterable that will take the place of the
    control code in the token list.
    '''
    raise NotImplementedError
  
  def also_uses(self):
    '''
    If implemented, this should return the fields that are also impact how the
    instruction is interpreted, such as flag fields.
    '''
    pass


class PercentPercent(ControlCode):
  '''print a literal %'''
  PATTERN = r'%%'
  
  def expand(self):
    return '%'

class PercentUpperS(ControlCode):
  '''print register (bits 3..5 as high number if bit 6 set)'''
  PATTERN = r'%S'
  
  def expand(self):
    return ComputedValue(
      name='hi_reg_6_1_and_3_3',
      children=[
        Field('hi_reg_upper', 6, 1),
        Field('hi_reg_lower', 3, 3),
      ]
    )

class PercentUpperD(ControlCode):  # FIXME: Incomplete
  '''print register (bits 0..2 as high number if bit 7 set)'''
  PATTERN = r'%D'

  def expand(self):
    return ComputedValue(
      name='hi_reg_7_1_and_0_3',
      children=[
        Field('hi_reg_upper', 7, 1),
        Field('hi_reg_lower', 0, 3),
      ]
    )

class PercentUpperN(ControlCode):
  '''print register mask (with LR)'''
  PATTERN = r'%N'
  
  def expand(self):
    a = []  # FIXME: Incomplete
    return ('{', *a, Register('lr'), '}')

class PercentUpperO(ControlCode):
  '''print register mask (with PC)'''  # FIXME: Incomplete
  PATTERN = r'%O'

  def expand(self):
    a = []  # FIXME: Incomplete
    return ('{', *a, Register('pc'), '}')

class PercentUpperM(ControlCode):
  '''print register mask'''
  PATTERN = r'%M'
  
  def expand(self):
    a = []  # FIXME: Incomplete
    return ('{', *a, '}')

class PercentLowerB(ControlCode):
  '''print CZB's 6-bit unsigned branch destination'''
  PATTERN = r'%b'
  
  def expand(self):
    # FIXME: Not used, so didn't bother to implement
    pass

class PercentLowerS(ControlCode):
  '''print right-shift immediate (6..10; 0 == 32).'''
  PATTERN = r'%s'
  
  def expand(self):
    return ComputedValue(
      'right_shift_imm_6_5',
      children=[ Field('imm', 6, 5) ]
    )

class PercentLowerC(ControlCode):
  '''print the condition code'''
  PATTERN = r'%c'
  
  def expand(self):
    if False:
      # The TC32 does not seem to have conditional instructions like Thumb
      return ContextVariable('cond', Register('flags'), 0, 4)
    return None

class PercentUpperC(ControlCode):
  '''print the condition code, or 's' if not conditional'''
  PATTERN = r'%C'
  
  def expand(self):
    if False:
      # The TC32 does not seem to have conditional instructions like Thumb
      return ComputedValue(
        'cond_or_s',
        children=[ ContextVariable('cond', Register('flags'), 0, 4) ]
      )
    return 's'

class PercentLowerX(ControlCode):
  '''print warning if conditional an not at end of IT block'''
  PATTERN = r'%x'
  
  def expand(self):
    # FIXME: just a comment; don't do anything
    pass

class PercentUpperX(ControlCode):
  '''print "\t; unpredictable <IT:code>" if conditional'''
  PATTERN = r'%X'
  
  def expand(self):
    # FIXME: just a comment; no-op it
    pass

class PercentUpperI(ControlCode):  # FIXME: Incomplete
  '''print IT instruction suffix and operands'''
  PATTERN = r'%I'

class PercentBitfieldLowerR(ControlCode):
  '''print bitfield as a register'''
  PATTERN = r'%(\d+)-(\d+)r'
  
  def expand(self, a, b):
    return Field('reg', int(a), int(b) - int(a) + 1)

class PercentBitfieldLowerD(ControlCode):
  '''print bitfield as decimal'''
  PATTERN = r'%(\d+)-(\d+)d'
  
  def expand(self, a, b):
    return Field('imm', int(a), int(b) - int(a) + 1, attributes=['dec'])

class PercentBitfieldUpperH(ControlCode):
  '''print (bitfield * 2) as decimal'''
  PATTERN = r'%(\d+)-(\d+)H'

  def expand(self, a, b):
    f = Field('imm', int(a), int(b) - int(a) + 1, attributes=['dec'])
    return ComputedValue(
      '%s_x2' % f.name,
      children=[f]
    )

class PercentBitfieldUpperW(ControlCode):
  '''print (bitfield * 4) as decimal'''
  PATTERN = r'%(\d+)-(\d+)W'
  
  def expand(self, a, b):
    f = Field('imm', int(a), int(b) - int(a) + 1, attributes=['dec'])
    return ComputedValue(
      '%s_x4' % f.name,
      children=[f]
    )

class PercentBitfieldLowerA(ControlCode):
  '''print (bitfield * 4) as a pc-rel offset'''
  PATTERN = r'%(\d+)-(\d+)a'
  
  def expand(self, a, b):
    # Should be (((pc + 4) & ~3) + (imm << 2)
    return ComputedField(
      'pc_rel_offset',
      children=[
        Field('imm', int(a), int(b) - int(a) + 1)
      ]
    )

class PercentBitfieldUpperB(ControlCode):
  '''print branch destination (signed displacement)'''
  PATTERN = r'%(\d+)-(\d+)B'
  
  def expand(self, a, b):
    return Field('displacement', int(a), int(b) - int(a) + 1,
      attributes=['signed'])

class PercentBitfieldLowerC(ControlCode):
  '''print bitfield as a condition code'''
  PATTERN = r'%(\d+)-(\d+)c'
  
  def expand(self, a, b):
    return Field('cond_imm', int(a), int(b) - int(a) + 1)

class PercentBitfieldLowerX(ControlCode):
  '''print bitfield as hexadecimal'''
  PATTERN = r'%(\d+)-(\d+)x'
  
  def expand(self, a, b):
    return Field('imm', int(a), int(b) - int(a) + 1, attributes=['hex'])

class PercentQuote(ControlCode):
  '''print char iff bit is one'''
  PATTERN = r'%(\d+)\'(.)'
  
  def expand(self, a, x):
    return Field('flag', int(a), 1)

class PercentQuestionMark(ControlCode):
  '''print first char if bit is one, else second'''
  PATTERN = r'%(\d+)\?(.)(.)'
  
  def expand(self, a, x, y):
    return Field('flag', int(a), 1)

class RegisterReference(ControlCode):
  '''
  This isn't a control code exactly, but a few of the assembler format strings
  contain hardcoded references to the `sp` and `pc` registers. We want to expand
  them to Register tokens.
  '''
  PATTERN = r'(^|\s|\[|,)(sp|pc)(,|\]|\s|$)'
  
  def expand(self, pre, reg, post):
    pre = [pre] if pre else []  # elide empty matches
    post = [post] if post else []
    return (*pre, Register(reg), *post)


################################################################################


# Parse all of the instructions' assembler format strings
_insns = []
for size, value, mask, asm in insns:
  # Normalize whitespace and strip comments
  asm = re.sub(r'\\t|\s+', ' ', asm)
  asm = re.sub(r'\s*;.*$', '', asm)
  
  # Tokenize: ['tand', '%C', ' ', '%0-2r', ',', ' ', '%3-5r']
  tokens = []
  for i, a in enumerate(re.split(r'\s+', asm)):
    pattern = r'|'.join(cc.PATTERN for cc in ControlCode.__subclasses__())
    pattern = pattern.replace('(', '(?:')
    pattern = r'(' + pattern + r')'
    parts = list(filter(lambda x: x, re.split(pattern, a)))
    tokens.extend(parts)
    tokens.append(' ')
  del tokens[-1]
  
  # Expand control codes
  while True:
    modified = False
    for i, token in enumerate(tokens):
      if not isinstance(token, str): continue
      for cc in ControlCode.__subclasses__():
        m = re.match(cc.PATTERN, token)
        if m:
          newtokens = cc().expand(*m.groups())
          try:
            tokens[i:i+1] = filter(lambda x: x is not None, newtokens)
          except TypeError:  # wasn't an iterable, make it one
            tokens[i:i+1] = filter(lambda x: x is not None, [newtokens])
          modified = True
          break
      if modified: break
    if not modified: break
  
  # Convert the list of tokens to a parent expression
  # Personally I don't really like the design of this, but what do I know.
  e = Expression()
  e.children = tokens
  
  # This is a bit gnarly, but we're basically converting the mask that objdump
  # uses to identify the instruction into the fields of the instruction that
  # we match against, and the values we expect those fields to hold.
  conditions = []
  maskbits = bin(mask)[2:].rjust(16, '0')[::-1]
  valuebits = bin(value)[2:].rjust(16, '0')[::-1]
  groups = re.findall(r'(0+|1+)', maskbits)
  offset = 0
  for g in groups:
    if g.startswith('1'):
      v = int(valuebits[offset:offset+len(g)][::-1] , 2)
      conditions.append((Field('op', offset, len(g)), v))
    offset += len(g)
  
  _insns.append((size, value, mask, asm, e, conditions))
insns = _insns
insns.sort(key=lambda x: x[3])  # sort by asm


################################################################################


# Generate the field map, which specifies all of the contiguous bitfields we
# will use from the instruction encoding.

allfields = set()
for size, _, _, _, e, conditions in insns:
  if size != 16: continue
  allfields.update(e.findall(lambda x: isinstance(x, Field)))
  allfields.update(f for f, v in conditions)

allfields = list(allfields)
allfields.sort(key=lambda x: x.name)

print('define token instruction(16)')
for field in allfields:
  print('  %s' % field.as_sleigh_definition())
print(';')

print()


################################################################################


# Generate the context variables, which are subfields of registers (like
# status flags).

contextregs = {}
for _, _, _, _, e, _ in insns:
    for v in e.findall(lambda x: isinstance(x, ContextVariable)):
      if v.register not in contextregs:
        contextregs[v.register] = set()
      contextregs[v.register].add(v)

for reg in sorted(contextregs.keys(), key=lambda x: x.name):
  print('define context %s' % reg.name)
  for var in contextregs[reg]:
    print('  %s' % var.as_sleigh_definition())
  print(';')

print()


################################################################################


# Generate the tables for the special variables

allcomputed = set()
for _, _, _, _, e, _ in insns:
  fields = e.findall(lambda x: isinstance(x, ComputedValue))
  allcomputed.update(fields)

allcomputed = list(allcomputed)
allcomputed.sort(key=lambda x: x.name)

for computed in allcomputed:
  print('%s: "fill me in!" is ' % computed.name, end='')
  print(' & '.join(f.name for f in computed.children \
    if isinstance(f, Expression)), end='')
  print(' { }')

print()


################################################################################


# Generate SLEIGH code from the instructions
for size, value, mask, asm, expr, conditions in insns:
  # Output the objdump specification as a comment
  print('#', asm)
  
  # Output the display section (see 7.3). This is a little ugly because we have
  # to figure out where to put quotation marks and the ^ character to
  # concatenate identifiers and literal characters.
  print(':%s' % expr.children[0], end='')
  prev_identifier = True
  for i, t in enumerate(expr.children[1:]):
    if t == ' ':
      print(' ', end='')
      prev_identifier = False
      continue
    
    if isinstance(t, Expression):
      if prev_identifier:
        print('^', end='')
      print(t.name, end='')
      prev_identifier = True
      continue
    prev_identifier = False
    
    if isinstance(t, str):
      if i == 0 and re.match('^[a-zA-Z_]+$', t):
        print(t, end = '')
      elif any(x.isalpha() for x in t):
        if prev_identifier:
          print('^', end='')
        print('"%s"' % t, end='')
      else:
        print(t, end='')
      continue
    
    raise ValueError('Unexpected token type', type(t))
  
  # Figure out the references we'll make
  refs = [ f for f in expr.children if isinstance(f, Expression) ]

  # Output the constraints
  print(' is ', end='')
  print(' & '.join('%s=0x%04x' % (f.name, v) for f, v in conditions), end='')
  if len(refs) and len(conditions):
    print(' & ', end='')
  print(' & '.join(f.name for f in refs), end='')
  print()
  print('{')
  print('}')
  print()


