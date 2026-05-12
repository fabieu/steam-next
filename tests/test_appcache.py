import os
import pytest
from steam.utils.appcache import parse_appinfo

def test_parse_v29_appinfo():
    test_file = os.path.join(os.path.dirname(__file__), 'test_data', 'appinfo_v29.vdf')
    assert os.path.exists(test_file), "V29 test data file missing"
    
    with open(test_file, 'rb') as f:
        header, apps_iter = parse_appinfo(f)
        
        # Verify Header
        assert header['magic'] == b")DV\x07"
        assert header['universe'] == 1
        
        apps = list(apps_iter)
        assert len(apps) == 1
        
        app = apps[0]
        # Verify App metadata
        assert app['appid'] == 12345
        assert app['change_number'] == 123
        
        # Verify payload resolved from string table
        data = app['data']
        assert 'appinfo' in data
        assert data['appinfo']['appid'] == 12345
        assert data['appinfo']['common']['name'] == 'Fake Game'
