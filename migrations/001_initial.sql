CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  auth_version integer NOT NULL DEFAULT 1 CHECK (auth_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email))),
  CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE organization_memberships (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  user_id uuid NOT NULL REFERENCES users(id),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  permission_key text NOT NULL UNIQUE CHECK (permission_key ~ '^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$'),
  description text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  is_system boolean NOT NULL DEFAULT false,
  is_owner boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX roles_name_per_org_unique ON roles (organization_id, lower(name));
CREATE UNIQUE INDEX one_owner_role_per_org ON roles (organization_id) WHERE is_owner;

CREATE TABLE role_permissions (
  organization_id uuid NOT NULL,
  role_id uuid NOT NULL,
  permission_id uuid NOT NULL REFERENCES permissions(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (organization_id, role_id) REFERENCES roles(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX role_permissions_permission_idx ON role_permissions(permission_id);

CREATE TABLE user_roles (
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role_id uuid NOT NULL,
  assigned_by uuid REFERENCES users(id),
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, user_id, role_id),
  FOREIGN KEY (organization_id, user_id)
    REFERENCES organization_memberships(organization_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, role_id)
    REFERENCES roles(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX user_roles_role_idx ON user_roles(organization_id, role_id);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id text NOT NULL CHECK (char_length(device_id) BETWEEN 8 AND 200),
  device_name text NOT NULL DEFAULT '' CHECK (char_length(device_name) <= 120),
  user_agent_hash text,
  ip_address inet,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoke_reason text,
  UNIQUE (user_id, device_id)
);
CREATE INDEX sessions_active_user_idx ON sessions(user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid NOT NULL,
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  parent_token_id uuid REFERENCES refresh_tokens(id),
  replaced_by_token_id uuid REFERENCES refresh_tokens(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_active_session_idx ON refresh_tokens(session_id, expires_at)
  WHERE revoked_at IS NULL AND consumed_at IS NULL;

CREATE TABLE password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX password_reset_active_user_idx ON password_reset_tokens(user_id, expires_at)
  WHERE consumed_at IS NULL;

CREATE TABLE organization_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (email = lower(btrim(email))),
  role_id uuid NOT NULL,
  token_hash char(64) NOT NULL UNIQUE,
  invited_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (organization_id, role_id) REFERENCES roles(organization_id, id)
);
CREATE UNIQUE INDEX one_active_invitation_per_email_org
  ON organization_invitations(organization_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);
CREATE INDEX projects_org_idx ON projects(organization_id, created_at DESC);

CREATE TABLE audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid REFERENCES organizations(id),
  actor_user_id uuid REFERENCES users(id),
  event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 3 AND 120),
  outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
  target_type text,
  target_id text,
  request_id text,
  ip_address inet,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_org_created_idx ON audit_logs(organization_id, created_at DESC);
CREATE INDEX audit_logs_actor_created_idx ON audit_logs(actor_user_id, created_at DESC);

CREATE FUNCTION protect_audit_logs() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit logs are append-only';
  END IF;
  IF OLD.created_at > now() - interval '90 days' THEN
    RAISE EXCEPTION 'audit logs cannot be deleted inside the retention window';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER audit_logs_append_only
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION protect_audit_logs();

CREATE TABLE outbox_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  topic text NOT NULL,
  payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  processed_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_ready_idx ON outbox_events(available_at, created_at)
  WHERE processed_at IS NULL;

INSERT INTO permissions(permission_key, description) VALUES
  ('org:read', 'Read organization details'),
  ('org:update', 'Update organization details'),
  ('org:delete', 'Archive an organization'),
  ('member:read', 'List organization members'),
  ('member:invite', 'Invite organization members'),
  ('member:remove', 'Remove organization members'),
  ('role:read', 'Read roles and their permissions'),
  ('role:create', 'Create custom roles'),
  ('role:update', 'Update custom roles and permissions'),
  ('role:delete', 'Delete custom roles'),
  ('role:assign', 'Assign roles to members'),
  ('permission:read', 'Read the permission catalog'),
  ('session:read', 'Read active sessions'),
  ('session:revoke', 'Revoke active sessions'),
  ('audit:read', 'Read organization audit events'),
  ('project:create', 'Create projects'),
  ('project:read', 'Read projects'),
  ('project:update', 'Update projects'),
  ('project:delete', 'Delete projects');
