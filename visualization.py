# visualization.py
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.patches import Rectangle


# Theme colors used by the GUI
PROCESS_COLOR = "#4A90E2"      # blue
RESOURCE_COLOR = "#50C878"     # green
DEADLOCK_COLOR = "#E24A4A"     # red
ALLOCATION_EDGE = "#555555"    # dark gray
REQUEST_EDGE = "#FF8C42"       # orange


class GraphVisualizer:
    def __init__(self, manager, canvas, fig_size=(6,4)):
        self.manager = manager
        self.canvas = canvas
        self.pos = None
        self.fig_size = fig_size

    def show_graph(self):
        graph = self.manager.allocation_graph
        fig = plt.Figure(figsize=self.fig_size, dpi=100)
        ax = fig.add_subplot(111)
        ax.clear()

        # Compute or reuse layout
        try:
            if self.pos is None or len(graph.nodes()) != len(self.pos):
                self.pos = nx.spring_layout(graph, k=1.2, iterations=100, seed=42)
        except Exception:
            self.pos = nx.spring_layout(graph, seed=42)

        # Determine node colors
        node_colors = []
        for n in graph.nodes():
            if n in self.manager.processes:
                node_colors.append(PROCESS_COLOR)
            elif n in self.manager.resources:
                node_colors.append(RESOURCE_COLOR)
            else:
                node_colors.append("#CCCCCC")

        # Highlight deadlock if present
        has_deadlock, deadlock_msg, cycles = self.manager.detect_deadlock()
        deadlock_nodes = set()
        deadlock_edges = set()
        if has_deadlock and cycles:
            for cycle in cycles:
                for u, v in cycle:
                    deadlock_nodes.add(u)
                    deadlock_nodes.add(v)
                    deadlock_edges.add((u, v))
            node_colors = [DEADLOCK_COLOR if n in deadlock_nodes else c for n, c in zip(graph.nodes(), node_colors)]

        # Draw nodes
        try:
            nx.draw_networkx_nodes(graph, self.pos, node_color=node_colors, node_size=1000, ax=ax, edgecolors="#222222", linewidths=0.8)
        except Exception:
            nx.draw(graph, self.pos, ax=ax)

        # Draw labels with instance info for resources
        labels = {}
        for n in graph.nodes():
            if n in self.manager.resources:
                total = self.manager.resource_instances.get(n, 1)
                allocated = self.manager.resource_allocated.get(n, 0)
                available = total - allocated
                labels[n] = f"{n}\n({available}/{total})"
            else:
                labels[n] = n

        try:
            nx.draw_networkx_labels(graph, self.pos, labels, font_size=8, font_weight='bold', ax=ax, font_color="#ffffff")
        except Exception:
            pass

        # Split edges
        allocation_edges = [(u, v) for u, v, d in graph.edges(data=True) if d.get('type') == 'allocation']
        request_edges = [(u, v) for u, v, d in graph.edges(data=True) if d.get('type') == 'request']

        if allocation_edges:
            nx.draw_networkx_edges(graph, self.pos, edgelist=allocation_edges, edge_color=ALLOCATION_EDGE, arrows=True, ax=ax, width=2)
        if request_edges:
            nx.draw_networkx_edges(graph, self.pos, edgelist=request_edges, edge_color=REQUEST_EDGE, arrows=True, ax=ax, width=2, style='dashed')

        # Emphasize deadlock edges if any
        if deadlock_edges:
            nx.draw_networkx_edges(graph, self.pos, edgelist=list(deadlock_edges), edge_color=DEADLOCK_COLOR, arrows=True, ax=ax, width=3)

        ax.set_title("Resource Allocation Graph (RAG)", fontsize=12, pad=10)
        ax.axis('off')

        # Add legend
        legend_elements = [
            Rectangle((0, 0), 1, 1, fc=PROCESS_COLOR, edgecolor='black', label='Process'),
            Rectangle((0, 0), 1, 1, fc=RESOURCE_COLOR, edgecolor='black', label='Resource'),
            Rectangle((0, 0), 1, 1, fc=DEADLOCK_COLOR, edgecolor='black', label='Deadlock'),
        ]
        ax.legend(handles=legend_elements, loc='upper right', fontsize=8, framealpha=0.9)

        # Update the Tk canvas
        for widget in self.canvas.winfo_children():
            widget.destroy()

        canvas_widget = FigureCanvasTkAgg(fig, master=self.canvas)
        canvas_widget.draw()
        canvas_widget.get_tk_widget().pack(fill="both", expand=True)
