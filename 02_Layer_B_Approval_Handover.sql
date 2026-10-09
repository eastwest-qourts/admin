-- EastWest Purple Pickle XP - Layer B APPROVAL-BASED WRITER HANDOVER (v5.11)
-- PREREQUISITE: 01_Layer_B_Base.sql must be successfully installed and an
-- authoritative private checkpoint must exist from Computer 1.
-- ADDITIVE: does not erase/move any tournament match, checkpoint or public feed.
-- A private shared publish key is NOT individual user authentication: device-bound
-- tokens distinguish browser sessions only. Rotate compromised private keys.
BEGIN;
DO $$ BEGIN
  IF to_regclass('public.ppx_admin_writer_leases') IS NULL OR
     to_regclass('public.ppx_admin_private_checkpoints') IS NULL OR
     to_regclass('public.ppx_admin_lease_audit') IS NULL THEN
     RAISE EXCEPTION 'Layer B base SQL must be installed first; no changes made';
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.ppx_admin_transfer_requests (
  request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id text NOT NULL,
  owner_device_id text NOT NULL,
  requester_device_id text NOT NULL,
  requester_device_label text NOT NULL,
  requester_token_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','declined','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now()+interval '5 minutes'),
  responded_at timestamptz,
  checkpoint_revision bigint,
  response_reason text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ppx_transfer_owner_pending_idx
  ON public.ppx_admin_transfer_requests (event_id, owner_device_id, created_at DESC) WHERE status='pending';
CREATE INDEX IF NOT EXISTS ppx_transfer_requester_idx
  ON public.ppx_admin_transfer_requests (event_id, requester_device_id, created_at DESC);
ALTER TABLE public.ppx_admin_transfer_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.ppx_admin_transfer_requests FROM PUBLIC,anon,authenticated;
-- No direct SELECT/INSERT/UPDATE permissions: only the SECURITY DEFINER RPCs below.

CREATE OR REPLACE FUNCTION public.ppx_admin_request_transfer(
  p_event_id text,p_device_id text,p_device_label text,p_lease_token text,p_admin_key text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,extensions AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE;
        cp public.ppx_admin_private_checkpoints%ROWTYPE;
        req uuid; now_t timestamptz:=clock_timestamp(); secret_hash text;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  IF length(coalesce(p_device_id,'')) NOT BETWEEN 8 AND 160 OR
     length(coalesce(p_device_label,'')) NOT BETWEEN 1 AND 80 OR
     length(coalesce(p_lease_token,'')) < 24 THEN
     RAISE EXCEPTION 'Invalid requesting device identity' USING ERRCODE='22023';
  END IF;
  secret_hash:=encode(extensions.digest(p_lease_token,'sha256'),'hex');
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS NULL OR l.expires_at<=now_t OR l.device_id=p_device_id THEN
    RETURN jsonb_build_object('ok',false,'error','No different active writer. Use Claim Control or wait for the primary to reconnect.');
  END IF;
  SELECT * INTO cp FROM public.ppx_admin_private_checkpoints WHERE event_id=p_event_id;
  IF NOT FOUND OR cp.revision<coalesce(l.last_revision,0) THEN
    RETURN jsonb_build_object('ok',false,'error','Primary checkpoint is absent or behind the known writer revision. Ask Computer 1 to Checkpoint Now.');
  END IF;
  UPDATE public.ppx_admin_transfer_requests SET status='cancelled',responded_at=now_t,response_reason='Superseded by new request'
  WHERE event_id=p_event_id AND requester_device_id=p_device_id AND status='pending';
  INSERT INTO public.ppx_admin_transfer_requests
    (event_id,owner_device_id,requester_device_id,requester_device_label,requester_token_hash,created_at,expires_at)
  VALUES(p_event_id,l.device_id,p_device_id,left(p_device_label,80),secret_hash,now_t,now_t+interval '5 minutes')
  RETURNING request_id INTO req;
  INSERT INTO public.ppx_admin_lease_audit(event_id,event_type,device_id,device_label,reason)
  VALUES(p_event_id,'transfer-request',p_device_id,left(p_device_label,80),'Requested approval from current writer');
  RETURN jsonb_build_object('ok',true,'request_id',req,'owner_label',l.device_label,'expires_at',now_t+interval '5 minutes');
END;$$;
REVOKE ALL ON FUNCTION public.ppx_admin_request_transfer(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_request_transfer(text,text,text,text,text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.ppx_admin_transfer_status(
  p_event_id text,p_device_id text,p_lease_token text,p_admin_key text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,extensions AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE;
        r public.ppx_admin_transfer_requests%ROWTYPE; tok_hash text;
        now_t timestamptz:=clock_timestamp(); is_owner boolean:=false;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  tok_hash:=encode(extensions.digest(coalesce(p_lease_token,''),'sha256'),'hex');
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id;
  is_owner:=coalesce(l.device_id=p_device_id AND l.lease_token_hash=tok_hash AND l.expires_at>now_t,false);
  IF is_owner THEN
    SELECT * INTO r FROM public.ppx_admin_transfer_requests
     WHERE event_id=p_event_id AND owner_device_id=p_device_id
       AND status='pending' AND expires_at>now_t
     ORDER BY created_at,request_id LIMIT 1;
    IF FOUND THEN RETURN jsonb_build_object('ok',true,'role','owner','status','pending',
      'request_id',r.request_id,'requester_label',r.requester_device_label,
      'requester_device_id',r.requester_device_id,'expires_at',r.expires_at); END IF;
    RETURN jsonb_build_object('ok',true,'role','owner','status','none');
  END IF;
  SELECT * INTO r FROM public.ppx_admin_transfer_requests
   WHERE event_id=p_event_id AND requester_device_id=p_device_id AND requester_token_hash=tok_hash
   ORDER BY created_at DESC,request_id DESC LIMIT 1;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok',true,'role','requester','status','none'); END IF;
  RETURN jsonb_build_object('ok',true,'role','requester',
    'status',CASE WHEN r.status='pending' AND r.expires_at<=now_t THEN 'expired' ELSE r.status END,
    'request_id',r.request_id,'expires_at',r.expires_at,'checkpoint_revision',r.checkpoint_revision,
    'response_reason',r.response_reason);
END;$$;
REVOKE ALL ON FUNCTION public.ppx_admin_transfer_status(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_transfer_status(text,text,text,text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.ppx_admin_decline_transfer(
  p_event_id text,p_request_id uuid,p_owner_device_id text,p_owner_lease_token text,p_admin_key text,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,extensions AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE; r public.ppx_admin_transfer_requests%ROWTYPE; now_t timestamptz:=clock_timestamp();
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS DISTINCT FROM p_owner_device_id OR
      l.lease_token_hash IS DISTINCT FROM encode(extensions.digest(coalesce(p_owner_lease_token,''),'sha256'),'hex') OR
      l.expires_at<=now_t THEN RETURN jsonb_build_object('ok',false,'error','Writer authority was lost.'); END IF;
  SELECT * INTO r FROM public.ppx_admin_transfer_requests WHERE event_id=p_event_id AND request_id=p_request_id FOR UPDATE;
  IF NOT FOUND OR r.status<>'pending' OR r.owner_device_id<>p_owner_device_id OR r.expires_at<=now_t THEN
      RETURN jsonb_build_object('ok',false,'error','Request is missing, expired or already resolved.'); END IF;
  UPDATE public.ppx_admin_transfer_requests SET status='declined',responded_at=now_t,response_reason=left(coalesce(p_reason,''),300) WHERE request_id=p_request_id;
  INSERT INTO public.ppx_admin_lease_audit(event_id,event_type,device_id,device_label,reason)
  VALUES(p_event_id,'transfer-declined',p_owner_device_id,l.device_label,'Request '||p_request_id::text||' declined: '||left(coalesce(p_reason,''),300));
  RETURN jsonb_build_object('ok',true,'status','declined');
END;$$;
REVOKE ALL ON FUNCTION public.ppx_admin_decline_transfer(text,uuid,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_decline_transfer(text,uuid,text,text,text,text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.ppx_admin_approve_transfer(
  p_event_id text,p_request_id uuid,p_owner_device_id text,p_owner_lease_token text,
  p_admin_key text,p_revision bigint,p_state jsonb,p_state_version integer
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,extensions AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE;
        r public.ppx_admin_transfer_requests%ROWTYPE;
        c public.ppx_admin_private_checkpoints%ROWTYPE;
        public_rev bigint;
        now_t timestamptz:=clock_timestamp();
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  -- Lock writer first, then the pending request: all ownership changes are serialized.
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS DISTINCT FROM p_owner_device_id OR
     l.lease_token_hash IS DISTINCT FROM encode(extensions.digest(coalesce(p_owner_lease_token,''),'sha256'),'hex') OR
     l.expires_at<=now_t THEN
     RETURN jsonb_build_object('ok',false,'error','Approval blocked: this device no longer holds the active writer lease.');
  END IF;
  SELECT * INTO r FROM public.ppx_admin_transfer_requests
   WHERE event_id=p_event_id AND request_id=p_request_id FOR UPDATE;
  IF NOT FOUND OR r.status<>'pending' OR r.expires_at<=now_t OR r.owner_device_id<>p_owner_device_id OR
     r.requester_device_id=p_owner_device_id THEN
     RETURN jsonb_build_object('ok',false,'error','Approval blocked: request expired, superseded or invalid.');
  END IF;
  IF coalesce(p_revision,0)<1 OR coalesce(p_state_version,0)<1 OR
     jsonb_typeof(p_state) IS DISTINCT FROM 'object' OR
     jsonb_typeof(p_state->'matches') IS DISTINCT FROM 'array' OR
     jsonb_typeof(p_state->'playoffs') IS DISTINCT FROM 'array' OR
     jsonb_typeof(p_state->'roster') IS DISTINCT FROM 'array' OR
     pg_column_size(p_state)>16777216 THEN
     RAISE EXCEPTION 'Invalid or oversized tournament checkpoint; ownership unchanged' USING ERRCODE='22023';
  END IF;
  SELECT * INTO c FROM public.ppx_admin_private_checkpoints WHERE event_id=p_event_id FOR UPDATE;
  SELECT version INTO public_rev FROM public.ppx_public_feed WHERE event_id=p_event_id;
  IF p_revision<greatest(coalesce(c.revision,0),coalesce(public_rev,0),coalesce(l.last_revision,0)) THEN
     RETURN jsonb_build_object('ok',false,'error','Approval blocked: local Admin revision is behind remote records. Save and reconcile before transferring.',
       'last_revision',greatest(coalesce(c.revision,0),coalesce(public_rev,0),coalesce(l.last_revision,0)));
  END IF;
  IF c.event_id IS NOT NULL AND c.revision=p_revision AND c.state IS DISTINCT FROM p_state THEN
     RETURN jsonb_build_object('ok',false,'error','Checkpoint differs from same remote revision; resolve collision before transfer.');
  END IF;
  -- Single transaction: validate/snapshot -> grant requester -> log approval.
  INSERT INTO public.ppx_admin_private_checkpoints
    (event_id,revision,state_version,state,device_id,device_label,reason,created_at)
  VALUES (p_event_id,p_revision,p_state_version,p_state,p_owner_device_id,left(l.device_label,80),
          'Atomic approved handover to '||left(r.requester_device_label,80),now_t)
  ON CONFLICT(event_id) DO UPDATE SET revision=excluded.revision,state_version=excluded.state_version,
    state=excluded.state,device_id=excluded.device_id,device_label=excluded.device_label,
    reason=excluded.reason,created_at=excluded.created_at;
  UPDATE public.ppx_admin_writer_leases SET device_id=r.requester_device_id,
    device_label=r.requester_device_label,lease_token_hash=r.requester_token_hash,
    last_revision=p_revision,expires_at=now_t+interval '120 seconds',updated_at=now_t
  WHERE event_id=p_event_id;
  UPDATE public.ppx_admin_transfer_requests SET status='approved',responded_at=now_t,checkpoint_revision=p_revision
  WHERE request_id=p_request_id;
  UPDATE public.ppx_admin_transfer_requests SET status='cancelled',responded_at=now_t,response_reason='Other request approved'
  WHERE event_id=p_event_id AND status='pending' AND request_id<>p_request_id AND owner_device_id=p_owner_device_id;
  INSERT INTO public.ppx_admin_lease_audit(event_id,event_type,device_id,device_label,reason)
    VALUES(p_event_id,'transfer-approved',p_owner_device_id,l.device_label,
      'Request '||p_request_id::text||': '||l.device_label||' -> '||r.requester_device_label||' at revision '||p_revision);
  RETURN jsonb_build_object('ok',true,'status','approved','checkpoint_revision',p_revision,
      'new_owner_label',r.requester_device_label);
END;$$;
REVOKE ALL ON FUNCTION public.ppx_admin_approve_transfer(text,uuid,text,text,text,bigint,jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_approve_transfer(text,uuid,text,text,text,bigint,jsonb,integer) TO anon,authenticated;
COMMIT;

-- Verify 4 new functions (without sharing keys):
-- SELECT proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON p.pronamespace=n.oid
-- WHERE n.nspname='public' AND proname IN
-- ('ppx_admin_request_transfer','ppx_admin_transfer_status','ppx_admin_decline_transfer','ppx_admin_approve_transfer')
-- ORDER BY proname;
