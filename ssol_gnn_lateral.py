import torch
from torch_geometric.nn import HeteroConv, GATConv
import torch.nn.functional as F

class SSOLGNNLateralMovementDetector(torch.nn.Module):
    def __init__(self, hidden_channels, out_channels):
        super().__init__()
        
        # Heterogeneous convolution layer utilizing Graph Attention
        self.conv1 = HeteroConv({
            ('process', 'spawns', 'process'): GATConv((-1, -1), hidden_channels, heads=2, add_self_loops=False),
            ('process', 'communicates', 'socket'): GATConv((-1, -1), hidden_channels, heads=2, add_self_loops=False),
            ('process', 'writes_to', 'file'): GATConv((-1, -1), hidden_channels, heads=2, add_self_loops=False),
            ('user', 'authenticates_to', 'process'): GATConv((-1, -1), hidden_channels, heads=2, add_self_loops=False)
        }, aggregation='mean')

        self.conv2 = HeteroConv({
            ('process', 'spawns', 'process'): GATConv((-1, -1), out_channels, heads=1, add_self_loops=False),
            ('process', 'communicates', 'socket'): GATConv((-1, -1), out_channels, heads=1, add_self_loops=False),
            ('process', 'writes_to', 'file'): GATConv((-1, -1), out_channels, heads=1, add_self_loops=False),
            ('user', 'authenticates_to', 'process'): GATConv((-1, -1), out_channels, heads=1, add_self_loops=False)
        }, aggregation='mean')

        # Fully connected layer outputting probability of lateral movement path
        self.classifier = torch.nn.Linear(out_channels, 1)

    def forward(self, x_dict, edge_index_dict):
        # Layer 1 message passing with Graph Attention
        h_dict = self.conv1(x_dict, edge_index_dict)
        h_dict = {key: F.elu(x) for key, x in h_dict.items()}
        
        # Layer 2 message passing
        h_dict = self.conv2(h_dict, edge_index_dict)
        h_dict = {key: F.elu(x) for key, x in h_dict.items()}

        # Extract Process Node embeddings for lateral path triage
        process_embeddings = h_dict['process']
        
        # Classification score for each active process path
        verdict = torch.sigmoid(self.classifier(process_embeddings))
        return verdict
