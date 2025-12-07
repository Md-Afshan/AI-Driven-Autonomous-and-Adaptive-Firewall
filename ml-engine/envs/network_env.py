import gym
import numpy as np
from gym import spaces

class NetworkEnv(gym.Env):
    """
    Simulated network environment for RL training.

    Observation: [packet_rate, syn_ack_ratio, cpu_load, conn_table_size]
    Action space:
      0 - Do nothing
      1 - Rate limit IP
      2 - Enable SYN cookies
      3 - Hard block IP

    Reward:
      +0.5 if cpu_load decreases
      +0.5 if packet_rate decreases
      -1 if legitimate traffic is dropped (false positive)

    The dynamics are stochastic and simplified for training.
    """

    def __init__(self, max_steps=200):
        super().__init__()
        # observation ranges
        # packet_rate: 0 - 30000
        # syn_ack_ratio: 0 - 100
        # cpu_load: 0 - 100
        # conn_table_size: 0 - 50000
        low = np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float32)
        high = np.array([30000.0, 100.0, 100.0, 50000.0], dtype=np.float32)
        self.observation_space = spaces.Box(low=low, high=high, dtype=np.float32)
        self.action_space = spaces.Discrete(4)

        self.max_steps = max_steps
        self.step_count = 0
        self.state = None
        self.done = False

    def reset(self):
        self.step_count = 0
        self.done = False
        # initialize with a mostly-normal state
        packet_rate = np.random.normal(2000, 800)
        syn_ack_ratio = np.random.uniform(0.5, 2.0)
        cpu_load = np.random.uniform(5, 30)
        conn_table_size = np.random.normal(2000, 800)
        self.state = np.array([packet_rate, syn_ack_ratio, cpu_load, conn_table_size], dtype=np.float32)
        return np.clip(self.state, self.observation_space.low, self.observation_space.high)

    def step(self, action):
        prev = self.state.copy()
        packet_rate, syn_ack_ratio, cpu_load, conn_table_size = prev

        # Background traffic dynamics
        # Small random fluctuations
        packet_rate += np.random.normal(0, packet_rate * 0.05)
        syn_ack_ratio += np.random.normal(0, 0.1)
        cpu_load += np.random.normal(0, 1.0)
        conn_table_size += np.random.normal(0, conn_table_size * 0.02)

        # Introduce random attack events with some probability
        if np.random.rand() < 0.05:
            # spike: SYN flood
            spike = np.random.uniform(8000, 25000)
            packet_rate += spike
            syn_ack_ratio += np.random.uniform(10, 80)
            cpu_load += np.random.uniform(10, 40)
            conn_table_size += np.random.uniform(2000, 20000)

        # Apply action effects
        # Actions reduce packet rate and/or cpu, but may cause false positives
        false_positive = False
        if action == 1:
            # rate limit: reduces packet_rate by 30-60% for the attacker, but may affect legitimate traffic sometimes
            reduction = packet_rate * np.random.uniform(0.3, 0.6)
            packet_rate -= reduction
            cpu_load -= reduction / 500.0
            # small chance of dropping legitimate traffic
            if np.random.rand() < 0.02:
                false_positive = True
        elif action == 2:
            # enable syn cookies: reduces connection table impact and cpu
            conn_table_size *= 0.6
            cpu_load -= np.random.uniform(1, 5)
        elif action == 3:
            # hard block: big reduction in packet_rate but higher false positive chance
            packet_rate *= np.random.uniform(0.0, 0.2)
            cpu_load -= np.random.uniform(5, 20)
            if np.random.rand() < 0.05:
                false_positive = True

        # clamp
        packet_rate = float(np.clip(packet_rate, 0.0, 30000.0))
        syn_ack_ratio = float(np.clip(syn_ack_ratio, 0.0, 100.0))
        cpu_load = float(np.clip(cpu_load, 0.0, 100.0))
        conn_table_size = float(np.clip(conn_table_size, 0.0, 50000.0))

        self.state = np.array([packet_rate, syn_ack_ratio, cpu_load, conn_table_size], dtype=np.float32)

        # Reward computation
        reward = 0.0
        if cpu_load < prev[2]:
            reward += 0.5
        if packet_rate < prev[0]:
            reward += 0.5
        if false_positive:
            reward -= 1.0

        self.step_count += 1
        if self.step_count >= self.max_steps:
            self.done = True

        info = {'false_positive': false_positive}
        return self.state, reward, self.done, info

    def render(self, mode='human'):
        print(f"step={self.step_count} state={self.state}")

    def close(self):
        pass
