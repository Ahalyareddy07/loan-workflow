CREATE TABLE roles (id SERIAL PRIMARY KEY, name VARCHAR(30) UNIQUE NOT NULL);
INSERT INTO roles(name) VALUES ('applicant'),('officer'),('analyst'),('manager'),('admin');

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  role_id INT NOT NULL REFERENCES roles(id),
  full_name VARCHAR(120) NOT NULL,
  email VARCHAR(160) UNIQUE NOT NULL,
  phone VARCHAR(30),
  password_hash TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE loan_products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(60) UNIQUE NOT NULL,
  annual_rate NUMERIC(5,2) NOT NULL,
  min_amount NUMERIC(14,2) NOT NULL,
  max_amount NUMERIC(14,2) NOT NULL,
  max_months INT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE
);
INSERT INTO loan_products(name,annual_rate,min_amount,max_amount,max_months) VALUES
 ('Personal',11.5,10000,2000000,84),('Home',8.6,500000,50000000,360),
 ('Auto',9.4,100000,5000000,84),('Education',9.0,50000,5000000,120),('Business',12.5,100000,20000000,120);

CREATE TYPE loan_status AS ENUM
 ('Submitted','Under Verification','Credit Assessment','Approved','Rejected','Disbursed','Closed');

CREATE TABLE loan_applications (
  id SERIAL PRIMARY KEY,
  applicant_id INT NOT NULL REFERENCES users(id),
  product_id INT NOT NULL REFERENCES loan_products(id),
  dob DATE, gender VARCHAR(12), address TEXT,
  employment_status VARCHAR(30), employer VARCHAR(120),
  monthly_income NUMERIC(14,2) NOT NULL CHECK (monthly_income > 0),
  liabilities NUMERIC(14,2) NOT NULL DEFAULT 0,
  amount NUMERIC(14,2) NOT NULL,
  purpose TEXT,
  months INT NOT NULL CHECK (months BETWEEN 6 AND 360),
  preferred_emi NUMERIC(14,2),
  status loan_status NOT NULL DEFAULT 'Submitted',
  docs_requested TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_status ON loan_applications(status);
CREATE INDEX idx_apps_applicant ON loan_applications(applicant_id);
CREATE INDEX idx_apps_created ON loan_applications(created_at);

CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  application_id INT NOT NULL REFERENCES loan_applications(id) ON DELETE CASCADE,
  doc_type VARCHAR(40) NOT NULL,
  file_name TEXT NOT NULL, stored_path TEXT NOT NULL, mime VARCHAR(80),
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_docs_app ON documents(application_id);

CREATE TABLE credit_assessments (
  id SERIAL PRIMARY KEY,
  application_id INT NOT NULL REFERENCES loan_applications(id) ON DELETE CASCADE,
  analyst_id INT NOT NULL REFERENCES users(id),
  risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  recommendation VARCHAR(10) NOT NULL,
  notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ca_app ON credit_assessments(application_id);

CREATE TABLE approvals (
  id SERIAL PRIMARY KEY,
  application_id INT NOT NULL REFERENCES loan_applications(id) ON DELETE CASCADE,
  approver_id INT NOT NULL REFERENCES users(id),
  decision VARCHAR(10) NOT NULL, comment TEXT,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id),
  message TEXT NOT NULL, read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notif_user ON notifications(user_id, read);

CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id),
  action TEXT NOT NULL, entity VARCHAR(40), entity_id INT, ip INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
