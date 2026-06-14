from kzb import KZBProcessor, pack_kzb
from pathlib import Path
def log(msg): pass
p = KZBProcessor(log)
#p.unpack(Path('e171.kzb'))
#print("Unpacked!")
pack_kzb(Path('e171.kzb_unpacked'), Path('e171_repacked.kzb'), log)
print("Packed!")
