def test_bool_dunders():
    bool_true = generic.BooleanObject(True)
    bool_false = generic.BooleanObject(False)
    assert bool_true != bool_false
    assert bool_true != ''
    assert bool_false != ''
    assert bool_true
    assert not bool_false
    assert bool_true == bool(bool_true)
    assert bool_false == bool(bool_false)

    assert repr(bool_true) == str(bool_true) == 'True'
    assert repr(bool_false) == str(bool_false) == 'False'
