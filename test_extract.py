from kzb import KZBProcessor
from pathlib import Path
p = KZBProcessor(lambda msg: None)
p.unpack(Path('e171.kzb'))
