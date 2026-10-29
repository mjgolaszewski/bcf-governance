"""UNRUN synthetic adverse controls; no real policy/admin/registry authority."""
from dataclasses import replace
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock
from .contracts import Admission, AdminSession, Mutation, Refused
from .normal_policy import InstalledPolicyControls, PolicyPin, PolicyObservation
from .admin_authority import AdminAuthority


class NormalPolicyControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        now=time.monotonic()
        self.admission=Admission('a'*64,'coordinator','controller','held','sandbox',now+60,now+120)
        self.session=AdminSession('synthetic-private-token','principal:synthetic','sandbox',now+200)
        self.mutation=Mutation('POST','/api/v1/admin/principals',b'{"synthetic":"private"}','admin_create_principal')
        self.pin=PolicyPin('a'*64,'synthetic-runtime-start','b'*64,'openbao-kms',
            '/app/src/chrysalis_identity/api/admin_context_policy.py','c'*64)
        self.deadline=now+50
        self.observations=[]
        self.observe=AsyncMock(side_effect=lambda *args: self.value())
        self.source=InstalledPolicyControls(pin=self.pin,observe_policy=self.observe,attest_policy=lambda *args:None)

    def value(self, **changed):
        return replace(PolicyObservation(self.pin,self.mutation.operation,self.mutation.method,
            self.mutation.path,False,True,True,time.monotonic()),**changed)

    async def authorize(self, source=None):
        return await (source or self.source).authorize(self.admission,self.mutation,self.session,self.deadline)

    async def consume(self, headers, source=None):
        return await (source or self.source).consume(self.admission,self.mutation,self.session,headers,self.deadline)

    async def test_attested_actual_noapproval_accepts_empty_headers_once(self):
        headers=await self.authorize();self.assertEqual(headers,{})
        self.assertIsNone(await self.consume(headers))
        with self.assertRaises(Refused):await self.consume(headers)

    async def test_candidate_json_observation_grants_nothing(self):
        self.observe.side_effect=None;self.observe.return_value={'requires_approval':False}
        with self.assertRaises(Refused):await self.authorize()

    async def test_boolean_attestor_is_not_independent_authority(self):
        for answer in (True,False):
            source=InstalledPolicyControls(pin=self.pin,observe_policy=self.observe,attest_policy=lambda *args:answer)
            with self.assertRaises(Refused):await self.authorize(source)

    async def test_stale_or_future_actual_policy_observation_refused(self):
        for delta in (-6,1):
            self.observe.side_effect=lambda *args:self.value(observed_at=time.monotonic()+delta)
            with self.assertRaises(Refused):await self.authorize()

    async def test_changed_runtime_config_or_profile_refused(self):
        for pin in (replace(self.pin,runtime_id='d'*64),replace(self.pin,configuration_sha256='d'*64),replace(self.pin,profile='foreign')):
            self.observe.side_effect=lambda *args:self.value(pin=pin)
            with self.assertRaises(Refused):await self.authorize()

    async def test_required_approval_never_falls_back_to_noapproval(self):
        self.observe.side_effect=lambda *args:self.value(requires_approval=True)
        with self.assertRaises(Refused):await self.authorize()

    async def test_real_intent_callback_only_when_policy_requires_approval(self):
        self.observe.side_effect=lambda *args:self.value(requires_approval=True)
        approved=AsyncMock(return_value={'x-identity-admin-mutation-intent':'synthetic-real-intent-fixture'})
        source=InstalledPolicyControls(pin=self.pin,observe_policy=self.observe,attest_policy=lambda *args:None,approved_intent=approved)
        headers=await self.authorize(source);await self.consume(headers,source)
        approved.assert_awaited_once()

    async def test_policy_change_before_http_refuses_consumed_authorization(self):
        headers=await self.authorize()
        self.observe.side_effect=lambda *args:self.value(requires_approval=True)
        with self.assertRaises(Refused):await self.consume(headers)
        self.assertEqual(self.source._pending,{})

    async def test_weaker_strongauth_or_stepup_never_accepted(self):
        for changed in ({'requires_strong_auth':False},{'requires_step_up':False}):
            self.observe.side_effect=lambda *args:self.value(**changed)
            with self.assertRaises(Refused):await self.authorize()

    async def test_foreign_mutation_policy_binding_refused(self):
        self.observe.side_effect=lambda *args:self.value(operation='foreign_operation')
        with self.assertRaises(Refused):await self.authorize()

    async def test_generic_empty_source_still_refused_before_http(self):
        http=SimpleNamespace(request=AsyncMock())
        authority=AdminAuthority(http,self.session,SimpleNamespace(authorize=AsyncMock(return_value={})),AsyncMock(return_value=None))
        with self.assertRaises(Refused):await authority.mutate(self.admission,self.mutation,deadline=self.deadline)
        http.request.assert_not_awaited()

    async def test_current_context_rechecked_after_policy_before_http(self):
        http=SimpleNamespace(request=AsyncMock())
        verify=AsyncMock(side_effect=[None,Refused()])
        authority=AdminAuthority(http,self.session,self.source,verify)
        with self.assertRaises(Refused):await authority.mutate(self.admission,self.mutation,deadline=self.deadline)
        self.assertEqual(verify.await_count,2);http.request.assert_not_awaited()

    async def test_correct_normal_policy_uses_real_bearer_without_control_header(self):
        http=SimpleNamespace(request=AsyncMock(return_value='synthetic-http-result'))
        authority=AdminAuthority(http,self.session,self.source,AsyncMock(return_value=None))
        self.assertEqual(await authority.mutate(self.admission,self.mutation,deadline=self.deadline),'synthetic-http-result')
        self.assertEqual(http.request.call_args.kwargs['control'],{})
        self.assertEqual(http.request.call_args.kwargs['token'],self.session.token)
