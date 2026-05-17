import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

class HardenedLSTMDetection(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_dim):
        super(HardenedLSTMDetection, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        # Bidirectional LSTM to capture backward dependencies (prevents evasion via suffix padding)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, 1) # Binary classification (normal vs exploit)
        
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        # Global max-pooling over time steps to prevent evasion via temporal dilation/slow delays
        pooled, _ = torch.max(lstm_out, dim=1)
        out = torch.sigmoid(self.fc(pooled))
        return out

def train_step_hardened(model, optimizer, sequence_batch, target_batch):
    model.train()
    optimizer.zero_grad()
    
    # 1. Adversarial sequence augmentation (injection of benign random padding tokens)
    augmented_sequence_batch = inject_adversarial_mimicry(sequence_batch)
    
    outputs = model(augmented_sequence_batch)
    
    # 2. Bounded Robust Loss function (prevents poisoning gradient shocks)
    loss = F.binary_cross_entropy(outputs, target_batch, reduction='none')
    
    # Apply gradient clipping to truncate gradient updates from large outlier poisoning clusters
    loss_mean = torch.mean(torch.clamp(loss, max=2.0))
    loss_mean.backward()
    
    # Clip global norm of gradients to resist poisoned baseline drift
    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
    optimizer.step()
    return loss_mean.item()

def inject_adversarial_mimicry(sequence_batch, padding_token_id=0):
    # Injects dummy benign system operations between malicious vectors
    # to simulate a mimicry bypass attempt during training.
    batch_size, seq_len = sequence_batch.shape
    device = sequence_batch.device
    augmented_sequences = []
    
    for seq in sequence_batch:
        aug_seq = []
        for token in seq:
            aug_seq.append(token.item())
            # 20% chance to inject benign noise to harden LSTM against mimicry padding
            if np.random.rand() < 0.20:
                aug_seq.append(padding_token_id)
        # Pad/truncate back to consistent length
        aug_seq = aug_seq[:seq_len]
        augmented_sequences.append(aug_seq)
        
    return torch.tensor(augmented_sequences, dtype=torch.long, device=device)
