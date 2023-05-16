CREATE TABLE user (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(100) NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE
);

INSERT INTO user (username, password, is_admin)
VALUES ('Sebastian', '$2b$12$zl6TfrfDLVuPpc6.RLMQTuduDKGV5ENdgv5CsI0T3OvFoYQLTgRBm', TRUE),
('Barto', '$2b$12$7Wt2a6PbtDTyMaHEk4q/u.olvwFumziBAnqjcn67vLRaOplZk4yH2', TRUE);
-- sin codificar es sebastian123 y el otro es barto123
