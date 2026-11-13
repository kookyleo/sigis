"""Export pyHanko 0.38.1's exact CLI oversized object-stream specimen (MIT)."""
from pathlib import Path
from pyhanko_testing_commons.test_data.samples import minimal_with_oversized_objstm

with Path(__file__).with_name('oversized.pdf').open('wb') as output:
    minimal_with_oversized_objstm().write(output)
