import json
from pathlib import Path
base=Path('/root/amber920/intoverflow/20260919T175806Z_1d444b1c')
for i in range(1,5):
    data=json.loads((base/'sinks'/f'sink_{i}.json').read_text())
    print('\nSINK',i,data['sink_function'],data['sink_address'],data['instruction'])
    for source in data['decompiled_sources']:
        if source['name']==data['sink_function']:
            print(source['code'])
    path=base/'llm'/f'sink_{i}_llm.json'
    if path.exists():
        result=json.loads(path.read_text())
        print('FINAL:',json.dumps(result['final_phase']['verdict'],indent=2))
