-- EastWest Ageas Purple Pickle XP — Layer B private Admin failover
-- Matches Admin v5.10 client RPC signatures. Event-specific, additive installation.
-- Apply in eastwest-qourts project only, in Supabase SQL Editor as a trusted DB admin.
-- First EXPORT a fresh Admin JSON backup on the original authoritative browser.
-- DO NOT run any recovery / takeover on a stale second device before a current private checkpoint exists.
-- Uses the existing PRIVATE publish key's SHA256 hash stored in ppx_public_feed_keys.
-- Never place the private publish key into this file or GitHub.
-- Installing these objects does NOT copy existing local tournament data to the cloud;
-- Claim and Checkpoint must be performed on the ORIGINAL Admin browser afterward.

BEGIN;

-- Scope data and avoid altering the existing public Player feed.
CREATE TABLE IF NOT EXISTS public.ppx_admin_writer_leases (
    event_id text PRIMARY KEY,
    device_id text,
    device_label text,
    lease_token_hash text,
    expires_at timestamptz,
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.ppx_admin_private_checkpoints (
    event_id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision >= 1),
    state_version integer NOT NULL CHECK (state_version >= 1),
    state jsonb NOT NULL,
    device_id text NOT NULL,
    device_label text NOT NULL,
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.ppx_admin_lease_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id text NOT NULL,
    event_type text NOT NULL,
    device_id text,
    device_label text,
    reason text NOT NULL DEFAULT '',
    event_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ppx_admin_lease_audit_by_event
  ON public.ppx_admin_lease_audit (event_id, event_at DESC);

-- No direct browser access to private state, lease token hashes, or audit history.
ALTER TABLE public.ppx_admin_writer_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ppx_admin_private_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ppx_admin_lease_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.ppx_admin_writer_leases FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ppx_admin_private_checkpoints FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ppx_admin_lease_audit FROM PUBLIC, anon, authenticated;
REVOKE ALL ON SEQUENCE public.ppx_admin_lease_audit_audit_id_seq FROM PUBLIC, anon, authenticated;

-- Internal verification; the public API cannot invoke this directly.
CREATE OR REPLACE FUNCTION public.ppx_admin_require_private_key(p_event_id text, p_admin_key text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE expected_hash text;
BEGIN
  IF p_event_id IS DISTINCT FROM 'EWA-2026-10-10-PURPLE-PICKLE-XP' THEN
    RAISE EXCEPTION 'Unexpected EastWest event ID' USING ERRCODE = '22023';
  END IF;
  SELECT k.publish_key_hash INTO expected_hash
  FROM public.ppx_public_feed_keys AS k WHERE k.event_id = p_event_id;
  IF expected_hash IS NULL OR p_admin_key IS NULL OR
     expected_hash IS DISTINCT FROM encode(extensions.digest(p_admin_key,'sha256'),'hex') THEN
    RAISE EXCEPTION 'Invalid private Admin credential' USING ERRCODE = '28000';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_require_private_key(text,text) FROM PUBLIC, anon, authenticated;

-- (1) Status check: called by both Admin devices during startup.
CREATE OR REPLACE FUNCTION public.ppx_admin_lease_status(p_event_id text, p_admin_key text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE; v_checkpoint bigint; v_public bigint;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id;
  SELECT c.revision INTO v_checkpoint FROM public.ppx_admin_private_checkpoints AS c WHERE c.event_id=p_event_id;
  SELECT f.version INTO v_public FROM public.ppx_public_feed AS f WHERE f.event_id=p_event_id;
  RETURN jsonb_build_object(
    'ok',true,
    'active',coalesce(l.device_id IS NOT NULL AND l.expires_at>clock_timestamp(),false),
    'device_id',l.device_id,'device_label',l.device_label,'expires_at',l.expires_at,
    'last_revision',greatest(coalesce(l.last_revision,0),coalesce(v_checkpoint,0),coalesce(v_public,0))
  );
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_lease_status(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_lease_status(text,text) TO anon, authenticated;

-- (2) Acquire or force takeover: atomic lease lock (120 second TTL).
CREATE OR REPLACE FUNCTION public.ppx_admin_acquire_lease(
  p_event_id text, p_device_id text, p_device_label text,
  p_lease_token text, p_admin_key text, p_force boolean,
  p_reason text, p_last_revision bigint
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE;
        v_hash text; v_now timestamptz; v_latest bigint; v_public bigint;
        v_checkpoint_exists boolean; v_had_active boolean;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  IF length(coalesce(p_device_id,'')) NOT BETWEEN 8 AND 160
    OR length(coalesce(p_device_label,'')) NOT BETWEEN 1 AND 80
    OR length(coalesce(p_lease_token,'')) < 24
    OR coalesce(p_last_revision,-1) < 0 THEN
    RAISE EXCEPTION 'Invalid device identity, lease token, or revision' USING ERRCODE='22023';
  END IF;
  IF coalesce(p_force,false) AND length(btrim(coalesce(p_reason,''))) < 6 THEN
    RAISE EXCEPTION 'Force takeover requires an explanation' USING ERRCODE='22023';
  END IF;
  v_hash:=encode(extensions.digest(p_lease_token,'sha256'),'hex');
  v_now:=clock_timestamp();
  INSERT INTO public.ppx_admin_writer_leases(event_id) VALUES(p_event_id)
  ON CONFLICT(event_id) DO NOTHING;
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  SELECT revision INTO v_latest FROM public.ppx_admin_private_checkpoints WHERE event_id=p_event_id;
  SELECT version INTO v_public FROM public.ppx_public_feed WHERE event_id=p_event_id;
  v_checkpoint_exists := v_latest IS NOT NULL;

  -- First time Layer B is enabled, only the up-to-date primary browser may claim it.
  IF NOT v_checkpoint_exists AND coalesce(p_last_revision,0) < coalesce(v_public,0) THEN
    RETURN jsonb_build_object('ok',false,'conflict',false,
      'error','Initialize Layer B from original Admin browser: this device revision is older than the public snapshot.',
      'last_revision',coalesce(v_public,0));
  END IF;

  v_had_active:=coalesce(l.device_id IS NOT NULL AND l.expires_at>v_now,false);
  IF v_had_active AND NOT (l.device_id=p_device_id AND l.lease_token_hash=v_hash)
      AND NOT coalesce(p_force,false) THEN
    RETURN jsonb_build_object('ok',false,'conflict',true,
      'owner_device_id',l.device_id,'owner_label',l.device_label,
      'expires_at',l.expires_at,'last_revision',greatest(l.last_revision,coalesce(v_latest,0)));
  END IF;

  UPDATE public.ppx_admin_writer_leases
  SET device_id=p_device_id,device_label=p_device_label,lease_token_hash=v_hash,
      expires_at=v_now+interval '120 seconds',
      last_revision=greatest(l.last_revision,coalesce(v_latest,0),coalesce(v_public,0)),updated_at=v_now
  WHERE event_id=p_event_id;

  -- Log only acquisition events (not every 30-second heartbeat).
  IF NOT v_had_active OR l.device_id IS DISTINCT FROM p_device_id OR l.lease_token_hash IS DISTINCT FROM v_hash THEN
    INSERT INTO public.ppx_admin_lease_audit(event_id,event_type,device_id,device_label,reason)
    VALUES(p_event_id,CASE WHEN v_had_active THEN 'force-takeover' ELSE 'claim' END,
           p_device_id,p_device_label,left(coalesce(p_reason,''),500));
  END IF;
  RETURN jsonb_build_object('ok',true,'expires_at',v_now+interval '120 seconds',
    'last_revision',greatest(l.last_revision,coalesce(v_latest,0),coalesce(v_public,0)));
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_acquire_lease(text,text,text,text,text,boolean,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_acquire_lease(text,text,text,text,text,boolean,text,bigint) TO anon, authenticated;

-- (3) Renew: only the current lease owner can renew.
CREATE OR REPLACE FUNCTION public.ppx_admin_renew_lease(
  p_event_id text, p_device_id text, p_lease_token text,
  p_admin_key text, p_last_revision bigint
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE; v_now timestamptz:=clock_timestamp();
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS DISTINCT FROM p_device_id OR
     l.lease_token_hash IS DISTINCT FROM encode(extensions.digest(coalesce(p_lease_token,''),'sha256'),'hex') THEN
    RETURN jsonb_build_object('ok',false,'conflict',true,
       'owner_device_id',l.device_id,'owner_label',l.device_label,'expires_at',l.expires_at);
  END IF;
  UPDATE public.ppx_admin_writer_leases SET expires_at=v_now+interval '120 seconds',updated_at=v_now,
     last_revision=greatest(last_revision,coalesce(p_last_revision,0)) WHERE event_id=p_event_id;
  RETURN jsonb_build_object('ok',true,'expires_at',v_now+interval '120 seconds');
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_renew_lease(text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_renew_lease(text,text,text,text,bigint) TO anon, authenticated;

-- (4) Release explicitly from original Admin; does NOT delete checkpoints.
CREATE OR REPLACE FUNCTION public.ppx_admin_release_lease(
  p_event_id text, p_device_id text, p_lease_token text,
  p_admin_key text, p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS DISTINCT FROM p_device_id OR
      l.lease_token_hash IS DISTINCT FROM encode(extensions.digest(coalesce(p_lease_token,''),'sha256'),'hex') THEN
    RETURN jsonb_build_object('ok',false,'error','This device does not own the writer lease');
  END IF;
  UPDATE public.ppx_admin_writer_leases
  SET device_id=NULL,device_label=NULL,lease_token_hash=NULL,expires_at=NULL,updated_at=clock_timestamp()
  WHERE event_id=p_event_id;
  INSERT INTO public.ppx_admin_lease_audit(event_id,event_type,device_id,device_label,reason)
  VALUES(p_event_id,'release',p_device_id,l.device_label,left(coalesce(p_reason,''),500));
  RETURN jsonb_build_object('ok',true);
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_release_lease(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_release_lease(text,text,text,text,text) TO anon, authenticated;

-- (5) Save private Admin checkpoint: only lease owner, monotonic revision,
--     never permit older browser data to overwrite published/remote history.
CREATE OR REPLACE FUNCTION public.ppx_admin_save_checkpoint(
  p_event_id text, p_revision bigint, p_state jsonb, p_state_version integer,
  p_device_id text, p_device_label text, p_lease_token text,
  p_admin_key text, p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE l public.ppx_admin_writer_leases%ROWTYPE; c public.ppx_admin_private_checkpoints%ROWTYPE;
        v_public_revision bigint; v_now timestamptz:=clock_timestamp();
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  IF coalesce(p_revision,0)<1 OR coalesce(p_state_version,0)<1 OR
     jsonb_typeof(p_state) IS DISTINCT FROM 'object' OR
     jsonb_typeof(p_state->'matches') IS DISTINCT FROM 'array' OR
     jsonb_typeof(p_state->'playoffs') IS DISTINCT FROM 'array' OR
     jsonb_typeof(p_state->'roster') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'Invalid complete Admin state or revision' USING ERRCODE='22023';
  END IF;
  IF pg_column_size(p_state)>16777216 THEN
    RAISE EXCEPTION 'Private Admin checkpoint too large (max 16 MB)' USING ERRCODE='22023';
  END IF;
  SELECT * INTO l FROM public.ppx_admin_writer_leases WHERE event_id=p_event_id FOR UPDATE;
  IF NOT FOUND OR l.device_id IS DISTINCT FROM p_device_id OR
     l.lease_token_hash IS DISTINCT FROM encode(extensions.digest(coalesce(p_lease_token,''),'sha256'),'hex') OR
     l.expires_at IS NULL OR l.expires_at<=v_now THEN
    RETURN jsonb_build_object('ok',false,'conflict',true,'error','Writer lease is not held by this device',
      'owner_device_id',l.device_id,'owner_label',l.device_label);
  END IF;
  SELECT * INTO c FROM public.ppx_admin_private_checkpoints WHERE event_id=p_event_id FOR UPDATE;
  SELECT version INTO v_public_revision FROM public.ppx_public_feed WHERE event_id=p_event_id;
  IF p_revision<greatest(coalesce(c.revision,0),coalesce(v_public_revision,0)) THEN
    RETURN jsonb_build_object('ok',false,'conflict',true,
       'error','Stale Admin revision: newer public/private state already exists',
       'last_revision',greatest(coalesce(c.revision,0),coalesce(v_public_revision,0)));
  END IF;
  IF c.event_id IS NOT NULL AND p_revision=c.revision AND p_state IS DISTINCT FROM c.state THEN
    RETURN jsonb_build_object('ok',false,'conflict',true,
       'error','Revision collision: existing private checkpoint has different content',
       'last_revision',c.revision);
  END IF;
  INSERT INTO public.ppx_admin_private_checkpoints
    (event_id,revision,state_version,state,device_id,device_label,reason,created_at)
  VALUES (p_event_id,p_revision,p_state_version,p_state,p_device_id,left(p_device_label,80),left(coalesce(p_reason,''),500),v_now)
  ON CONFLICT(event_id) DO UPDATE SET revision=excluded.revision,state_version=excluded.state_version,
      state=excluded.state,device_id=excluded.device_id,device_label=excluded.device_label,
      reason=excluded.reason,created_at=excluded.created_at;
  UPDATE public.ppx_admin_writer_leases SET last_revision=greatest(last_revision,p_revision),
       updated_at=v_now WHERE event_id=p_event_id;
  RETURN jsonb_build_object('ok',true,'revision',p_revision,'updated_at',v_now);
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_save_checkpoint(text,bigint,jsonb,integer,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_save_checkpoint(text,bigint,jsonb,integer,text,text,text,text,text) TO anon, authenticated;

-- (6) Recover private state: only someone knowing the Admin private key.
CREATE OR REPLACE FUNCTION public.ppx_admin_latest_checkpoint(p_event_id text, p_admin_key text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions
AS $$
DECLARE c public.ppx_admin_private_checkpoints%ROWTYPE;
BEGIN
  PERFORM public.ppx_admin_require_private_key(p_event_id,p_admin_key);
  SELECT * INTO c FROM public.ppx_admin_private_checkpoints WHERE event_id=p_event_id;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok',true,'found',false,'revision',0); END IF;
  RETURN jsonb_build_object('ok',true,'found',true,'revision',c.revision,
    'state',c.state,'state_version',c.state_version,'device_id',c.device_id,
    'device_label',c.device_label,'reason',c.reason,'created_at',c.created_at);
END;
$$;
REVOKE ALL ON FUNCTION public.ppx_admin_latest_checkpoint(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ppx_admin_latest_checkpoint(text,text) TO anon, authenticated;

COMMIT;

-- Verify function installation without revealing any credentials:
-- SELECT p.proname AS function_name
-- FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
-- WHERE n.nspname='public' AND p.proname IN (
--   'ppx_admin_lease_status','ppx_admin_acquire_lease','ppx_admin_renew_lease',
--   'ppx_admin_release_lease','ppx_admin_save_checkpoint','ppx_admin_latest_checkpoint')
-- ORDER BY p.proname;
-- Expected 6 rows. PRIVATE checkpoint remains empty until the ORIGINAL Admin claims the lease.
