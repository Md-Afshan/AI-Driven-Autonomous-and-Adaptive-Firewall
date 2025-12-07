from stable_baselines3 import PPO
import numpy as np
m = PPO.load('C:/Users/admin/OneDrive/Desktop/PROJECT/ml-engine/models/ppo_network_final')
obs_attack = np.array([15000.0, 20.0, 80.0, 15000.0], dtype=float)
obs_normal = np.array([50.0, 1.0, 10.0, 1000.0], dtype=float)
print('attack ->', m.predict(obs_attack, deterministic=True))
print('normal ->', m.predict(obs_normal, deterministic=True))
