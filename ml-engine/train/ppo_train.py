"""
Train an RL agent (PPO) on the NetworkEnv and save the trained model.

Run: python ppo_train.py
"""
import os
import sys
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.callbacks import CheckpointCallback

# Ensure ml-engine directory is discoverable when running from repo root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from envs.network_env import NetworkEnv

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models'))
os.makedirs(MODEL_DIR, exist_ok=True)

def make_env():
    return NetworkEnv()

def train(total_timesteps=200_000):
    env = DummyVecEnv([make_env])
    checkpoint_callback = CheckpointCallback(save_freq=50_000, save_path=MODEL_DIR, name_prefix='ppo_network')
    model = PPO('MlpPolicy', env, verbose=1)
    model.learn(total_timesteps=total_timesteps, callback=checkpoint_callback)
    model.save(os.path.join(MODEL_DIR, 'ppo_network_final'))
    print('Saved model to', MODEL_DIR)

if __name__ == '__main__':
    train()
