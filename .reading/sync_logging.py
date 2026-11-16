from pathlib import Path
import shutil
import time
src=Path('/mnt/c/Users/ROG/Desktop/mango_0')
dst=Path('/root/mango_0')
backup=dst/'.repair_backups'/('logging_'+time.strftime('%Y%m%dT%H%M%S'))
for relative in ['package/argument_resolver/analysis/integer_overflow.py','package/argument_resolver/utils/integer_overflow_detection.py','package/argument_resolver/utils/width_screening.py','package/argument_resolver/utils/overflow_logging.py','package/tests/test_overflow_logging.py']:
    target=dst/relative
    if target.exists():
        saved=backup/relative
        saved.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(target,saved)
    shutil.copy2(src/relative,target)
print('Synced logging changes; backups:',backup)
