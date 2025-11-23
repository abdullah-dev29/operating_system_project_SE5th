# allocation.py
import networkx as nx


class ResourceManager:
    def __init__(self):
        self.allocation_graph = nx.DiGraph()
        self.resources = set()
        self.processes = set()

        # Multi-instance resource support
        self.resource_instances = {}  # {resource: total_instances}
        self.resource_allocated = {}  # {resource: allocated_count}
        self.process_allocation = {}  # {(process, resource): count}

        # NEW: Pending requests queue
        self.pending_requests = []  # [{process, resource, instances}]

    def request_resource(self, process, resource, instances=1):
        """
        Process requests a resource - goes into pending queue for approval
        """
        process = str(process)
        resource = str(resource)
        instances = int(instances)

        self.processes.add(process)
        self.resources.add(resource)
        self.allocation_graph.add_node(process)
        self.allocation_graph.add_node(resource)

        # Initialize resource instances if first time
        if resource not in self.resource_instances:
            self.resource_instances[resource] = instances
            self.resource_allocated[resource] = 0

        # Add to pending requests
        request = {
            'process': process,
            'resource': resource,
            'instances': instances
        }
        self.pending_requests.append(request)

        # Add request edge to graph (dashed line)
        if not self.allocation_graph.has_edge(process, resource):
            self.allocation_graph.add_edge(process, resource, type='request')

        return f"{process} requested {resource} - PENDING APPROVAL (use 'View Pending Requests' to approve)"

    def approve_request(self, process, resource):
        """
        Approve a pending request and allocate the resource
        """
        process = str(process)
        resource = str(resource)

        # Find and remove from pending
        request = None
        for req in self.pending_requests:
            if req['process'] == process and req['resource'] == resource:
                request = req
                self.pending_requests.remove(req)
                break

        if request:
            # Allocate the resource
            return self.allocate(process, resource, request['instances'])
        else:
            return f"No pending request found for {process} -> {resource}"

    def get_pending_requests(self):
        """Return list of pending requests"""
        return self.pending_requests.copy()

    def allocate(self, process, resource, instances=1):
        """
        Direct allocation (immediate, no approval needed)
        If resource is free -> add allocation edge: resource -> process (type='allocation')
        If resource is taken -> add request edge: process -> resource (type='request')
        Now supports multiple instances per resource.
        """
        process = str(process)
        resource = str(resource)
        instances = int(instances)

        self.processes.add(process)
        self.resources.add(resource)
        self.allocation_graph.add_node(process)
        self.allocation_graph.add_node(resource)

        # Initialize resource instances if first time
        if resource not in self.resource_instances:
            self.resource_instances[resource] = instances
            self.resource_allocated[resource] = 0

        # Check available instances
        available = self.resource_instances[resource] - self.resource_allocated[resource]

        if available > 0:
            # Allocate one instance
            self.resource_allocated[resource] += 1

            # Track process allocation
            key = (process, resource)
            self.process_allocation[key] = self.process_allocation.get(key, 0) + 1

            # Remove any existing request edge
            if self.allocation_graph.has_edge(process, resource):
                self.allocation_graph.remove_edge(process, resource)

            # Add allocation edge: Resource -> Process
            if not self.allocation_graph.has_edge(resource, process):
                self.allocation_graph.add_edge(resource, process, type='allocation')

            return f"✓ Allocated {resource} to {process} (available: {available-1}/{self.resource_instances[resource]})"
        else:
            # Add request edge: Process -> Resource
            if not self.allocation_graph.has_edge(process, resource):
                self.allocation_graph.add_edge(process, resource, type='request')
            return f"⚠ {process} requested {resource} (all {self.resource_instances[resource]} instances in use)"

    def release(self, process, resource):
        process = str(process)
        resource = str(resource)

        key = (process, resource)

        # Check if this process has this resource allocated
        if key in self.process_allocation and self.process_allocation[key] > 0:
            self.process_allocation[key] -= 1
            self.resource_allocated[resource] -= 1

            # If no more instances allocated, remove allocation edge
            if self.process_allocation[key] == 0:
                del self.process_allocation[key]
                if self.allocation_graph.has_edge(resource, process):
                    self.allocation_graph.remove_edge(resource, process)

            # Try to allocate to waiting processes
            for p in list(self.allocation_graph.predecessors(resource)):
                if self.allocation_graph.has_edge(p, resource) and self.allocation_graph[p][resource].get('type') == 'request':
                    self.allocation_graph.remove_edge(p, resource)
                    self.allocate(p, resource)
                    break

            # Cleanup nodes with degree 0
            if self.allocation_graph.degree(process) == 0:
                try:
                    self.allocation_graph.remove_node(process)
                    if process in self.processes:
                        self.processes.remove(process)
                except Exception:
                    pass

            if self.allocation_graph.degree(resource) == 0:
                try:
                    self.allocation_graph.remove_node(resource)
                    if resource in self.resources:
                        self.resources.remove(resource)
                    if resource in self.resource_instances:
                        del self.resource_instances[resource]
                    if resource in self.resource_allocated:
                        del self.resource_allocated[resource]
                except Exception:
                    pass

            avail = self.resource_instances.get(resource, 0) - self.resource_allocated.get(resource, 0)
            total = self.resource_instances.get(resource, 0)
            return f"✓ Released {resource} from {process} (available: {avail}/{total})"

        return f"✗ No allocation of {resource} to {process} exists"

    def detect_deadlock(self):
        """
        Detect cycles composed of allocation + request edges (a true RAG deadlock).
        Returns (has_deadlock: bool, message: str, cycles_edges: list)
        """
        try:
            cycles = list(nx.simple_cycles(self.allocation_graph))
            deadlock_cycles = []

            for cycle in cycles:
                has_allocation = False
                has_request = False
                cycle_edges = []

                for i in range(len(cycle)):
                    u = cycle[i]
                    v = cycle[(i + 1) % len(cycle)]
                    if self.allocation_graph.has_edge(u, v):
                        edge_type = self.allocation_graph[u][v].get('type', '')
                        cycle_edges.append((u, v))
                        if edge_type == 'allocation':
                            has_allocation = True
                        elif edge_type == 'request':
                            has_request = True

                if has_allocation and has_request:
                    deadlock_cycles.append(cycle_edges)

            if deadlock_cycles:
                first_cycle_nodes = {u for edge in deadlock_cycles[0] for u in edge}
                suggested_process = next((n for n in first_cycle_nodes if n in self.processes), None)
                suggestion = f"Suggested recovery: terminate {suggested_process}" if suggested_process else "Suggested recovery: release some resource(s)"
                return True, f"⚠ Deadlock Detected! Cycles: {deadlock_cycles}. {suggestion}", deadlock_cycles

            return False, "✓ No Deadlock Detected", []
        except Exception as e:
            return False, f"✗ Error in deadlock detection: {str(e)}", []

    def check_safety(self):
        """
        Implements Banker's Algorithm to check if system is in safe state.
        Returns (is_safe: bool, message: str, safe_sequence: list)
        """
        try:
            if not self.processes:
                return True, "✓ System is empty (safe by default)", []

            available = {}
            for resource in self.resources:
                total = self.resource_instances.get(resource, 1)
                allocated = self.resource_allocated.get(resource, 0)
                available[resource] = total - allocated

            allocation = {}
            for process in self.processes:
                allocation[process] = {}
                for resource in self.resources:
                    key = (process, resource)
                    allocation[process][resource] = self.process_allocation.get(key, 0)

            need = {}
            for process in self.processes:
                need[process] = {}
                for resource in self.resources:
                    if self.allocation_graph.has_edge(process, resource):
                        need[process][resource] = 1
                    else:
                        need[process][resource] = 0

            work = available.copy()
            finish = {p: False for p in self.processes}
            safe_sequence = []

            while len(safe_sequence) < len(self.processes):
                found = False

                for process in self.processes:
                    if not finish[process]:
                        can_proceed = True
                        for resource in self.resources:
                            if need[process].get(resource, 0) > work.get(resource, 0):
                                can_proceed = False
                                break

                        if can_proceed:
                            for resource in self.resources:
                                work[resource] = work.get(resource, 0) + allocation[process].get(resource, 0)
                            finish[process] = True
                            safe_sequence.append(process)
                            found = True
                            break

                if not found:
                    unfinished = [p for p in self.processes if not finish[p]]
                    return False, f"⚠ System is UNSAFE! Processes {unfinished} cannot complete.", []

            return True, f"✓ System is SAFE! Safe sequence: {' → '.join(safe_sequence)}", safe_sequence

        except Exception as e:
            return False, f"✗ Error in safety check: {str(e)}", []

    def terminate_process(self, process):
        """
        Terminates a process and releases all its resources.
        Used for deadlock recovery.
        """
        process = str(process)

        if process not in self.processes:
            return f"✗ Process {process} does not exist"

        resources_to_release = []
        for (p, r) in list(self.process_allocation.keys()):
            if p == process:
                resources_to_release.append(r)

        for resource in resources_to_release:
            while (process, resource) in self.process_allocation:
                self.release(process, resource)

        edges_to_remove = []
        for u, v in self.allocation_graph.edges():
            if u == process or v == process:
                edges_to_remove.append((u, v))

        for u, v in edges_to_remove:
            self.allocation_graph.remove_edge(u, v)

        if self.allocation_graph.has_node(process):
            self.allocation_graph.remove_node(process)

        if process in self.processes:
            self.processes.remove(process)

        # Remove any pending requests from this process
        self.pending_requests = [req for req in self.pending_requests if req['process'] != process]

        return f"✓ Process {process} terminated and all resources released"

    def clear_all(self):
        self.allocation_graph.clear()
        self.processes.clear()
        self.resources.clear()
        self.resource_instances.clear()
        self.resource_allocated.clear()
        self.process_allocation.clear()
        self.pending_requests.clear()
        return "✓ All allocations, requests, and pending requests have been cleared"
