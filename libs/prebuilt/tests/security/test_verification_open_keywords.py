"""Native keyword dictionaries retain unknown keys, values and forwarding paths."""

import pytest

from tests.security.test_verification_forwarding import check


@pytest.mark.parametrize("read", ["kwargs['call']", "kwargs.get('call')"])
def test_repeated_projection_keeps_the_authorized_identity(read):
    report = check(
        f"""
        call = {read}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, {read})
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "copy", ["kwargs.copy()", "dict(kwargs)", "MappingProxyType(kwargs)"]
)
def test_copies_and_proxies_share_original_values_and_presence(copy):
    report = check(
        f"""
        copied = {copy}
        call = kwargs.get('call')
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, copied.get('call'))
    """,
        "from types import MappingProxyType\n",
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


def test_absence_guard_keeps_the_dispatch_request_on_the_default_branch():
    report = check(
        """
        if 'call' in kwargs:
            raise PermissionError('unexpected request')
        call = kwargs.get('call', request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, call)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report


def test_an_unknown_key_cannot_be_assumed_absent():
    report = check(
        """
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, kwargs.get('call', request))
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["entries"][0]["status"] == "violated", report
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_kwargs_excludes_named_parameters_that_python_already_bound():
    report = check(
        """
        if 'principal' in kwargs or 'request' in kwargs:
            return dispatch(None, None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report


def test_positional_only_names_can_still_appear_in_kwargs():
    report = check(
        """
        if 'principal' in kwargs:
            return dispatch(principal, request)
    """,
        signature="self, principal, request, /, **kwargs",
    )
    assert report["entries"][0]["status"] == "violated", report


@pytest.mark.parametrize("mutation", ["del kwargs['call']", "kwargs.pop('call')"])
def test_deletion_does_not_change_the_value_in_a_prior_shallow_copy(mutation):
    report = check(
        f"""
        copied = kwargs.copy()
        call = kwargs['call']
        {mutation}
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, copied['call'])
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


@pytest.mark.parametrize("mutation", ["del kwargs['call']", "kwargs.pop('call', None)"])
def test_deleted_keys_cannot_reappear_from_the_unknown_remainder(mutation):
    report = check(
        f"""
        {mutation}
        if 'call' in kwargs:
            return dispatch(None, None)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report


def test_setdefault_retains_both_the_existing_and_inserted_value_paths():
    report = check(
        """
        call = kwargs.setdefault('call', request)
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, kwargs['call'])
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report


def test_replacing_an_authorized_mapping_value_revokes_the_mapping_grant():
    report = check(
        """
        d = permission(principal, kwargs)
        if d.verdict is Verdict.ALLOW:
            kwargs['call'] = request
            return dispatch(principal, kwargs)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["entries"][0]["status"] == "violated", report


def test_forwarding_to_a_required_signature_analyzes_all_valid_bindings():
    report = check(
        "return execute(**kwargs)",
        """
        def execute(principal, request):
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """,
        signature="self, **kwargs",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_forwarded_unknown_keys_can_reach_an_unchecked_dispatch():
    report = check(
        "return execute(**kwargs)",
        """
        def execute(principal, request):
            return dispatch(principal, request)
    """,
        signature="self, **kwargs",
    )
    assert report["entries"][0]["status"] == "violated", report


def test_extra_keyword_remainder_survives_multiple_helper_calls():
    report = check(
        "return relay(principal, **kwargs)",
        """
        def relay(principal, **extras):
            return execute(principal, **extras)
        def execute(principal, **extras):
            call = extras.get('call')
            d = permission(principal, call)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, extras.get('call'))
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


def test_forwarded_remainder_is_not_treated_as_an_empty_dict():
    report = check(
        "return relay(principal, **kwargs)",
        """
        def relay(principal, **extras):
            if 'call' in extras:
                return dispatch(principal, extras['call'])
    """,
        signature="self, principal, **kwargs",
    )
    assert report["entries"][0]["status"] == "violated", report


def test_native_forwarding_copies_kwargs_before_callee_deletion():
    report = check(
        """
        call = kwargs['call']
        erase(**kwargs)
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, kwargs['call'])
    """,
        """
        def erase(**extras):
            extras.pop('call', None)
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


def test_keyword_expansion_snapshots_before_later_arguments_mutate_the_source():
    report = check(
        """
        if 'marker' in kwargs:
            raise PermissionError('reserved')
        call = kwargs['call']
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return execute(principal, **kwargs, marker=erase(kwargs))
    """,
        """
        def erase(values):
            values.pop('call', None)
            return None
        def execute(principal, call, marker=None):
            return dispatch(principal, call)
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


def test_unread_keyword_remainder_is_also_snapshotted_before_later_mutation():
    report = check(
        """
        if 'marker' in kwargs:
            raise PermissionError('reserved')
        return execute(principal, **kwargs, marker=prepare(principal, kwargs))
    """,
        """
        def prepare(principal, values):
            call = values.pop('call', None)
            return permission(principal, call)
        def execute(principal, call=None, marker=None):
            if marker.verdict is Verdict.ALLOW:
                return dispatch(principal, call)
    """,
        signature="self, principal, **kwargs",
    )
    assert report["complete"], report


def test_empty_keyword_guard_closes_only_the_guarded_mapping():
    report = check(
        """
        if kwargs:
            raise PermissionError('extra arguments')
        return execute(principal, request, **kwargs)
    """,
        """
        def execute(principal, request):
            d = permission(principal, request)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report


def test_duplicate_keyword_prevents_callee_body_execution():
    report = check(
        """
        kwargs['request'] = request
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, request)
        execute(principal, request, **kwargs)
    """,
        """
        def execute(principal, request):
            dispatch(None, None)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1


def test_binding_exception_reaches_enclosing_handler_without_authority():
    report = check(
        """
        try:
            execute(**kwargs)
        except TypeError:
            dispatch(principal, request)
    """,
        """
        def execute(required):
            return None
    """,
        signature="self, principal, request, **kwargs",
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_open_mappings_cannot_be_used_as_finite_iteration_inventories():
    report = check(
        """
        for name in kwargs:
            dispatch(principal, request)
    """,
        signature="self, principal, request, **kwargs",
    )
    assert not report["complete"]
    assert any(
        "unbounded-key" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


def test_native_keyword_packing_contract_uses_only_inert_values():
    value = object()

    def receive(named, /, **extras):
        return extras

    original = {"named": value, "other": value}
    packed = receive(None, **original)
    assert packed is not original
    assert packed["named"] is value
    packed.pop("other")
    assert original["other"] is value

    class InertKey(str):
        pass

    key = InertKey("extra")
    subclass_packed = receive(None, **{key: value})
    assert next(iter(subclass_packed)) is key


def test_custom_hash_protocol_is_not_silently_accepted_for_keyword_keys():
    report = check(
        """
        call = kwargs.get('call')
        d = permission(principal, call)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, call)
    """,
        """
        class CustomKey:
            def __hash__(self):
                return 1
    """,
        signature="self, principal, **kwargs",
    )
    assert not report["complete"]
    assert any(
        "custom Python object protocol" in item["reason"] for item in report["issues"]
    )
