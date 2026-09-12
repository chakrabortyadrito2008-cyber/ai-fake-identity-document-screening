import networkx as nx
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class GraphAnalysis(Detector):
    name="graph_analysis"
    def __init__(self, repository): self.repository=repository
    def analyse(self, context):
        if not context.config["features"]["graph"]: return [EvidenceResult(self.name,"identity_graph",DetectorStatus.UNAVAILABLE)]
        sha=context.metadata["fingerprint"]["sha256"]; submitted=context.submission.get("identity_key")
        g=nx.Graph()
        for record in self.repository.graph_records(context.config.get("processing", {}).get("max_graph_nodes", 1000)):
            artifact = "sha:" + record["sha256"]; g.add_node(artifact, kind="artifact")
            if record["identity_key"]:
                node = "identity:" + record["identity_key"]; g.add_edge(artifact, node, relation="SUBMITTED_AS")
            for field, value in record["fields"].items():
                if field in {"id_number", "phone", "address", "name", "date_of_birth"}:
                    g.add_edge(artifact, f"{field}:{value}", relation="EXTRACTED_FIELD")
        current = "sha:" + sha; g.add_node(current, kind="artifact")
        if submitted: g.add_edge(current, "identity:" + submitted, relation="SUBMITTED_AS")
        for field in context.fields:
            if field.name in {"id_number", "phone", "address", "name", "date_of_birth"} and field.normalized_value:
                g.add_edge(current, f"{field.name}:{field.normalized_value}", relation="EXTRACTED_FIELD")
        component = next((part for part in nx.connected_components(g) if current in part), {current})
        artifact_nodes = [node for node in component if node.startswith("sha:")]
        identity_nodes = [node for node in component if node.startswith("identity:")]
        context.metadata["graph"]={"nodes":g.number_of_nodes(),"edges":g.number_of_edges(),"component_nodes":len(component),"related_artifacts":max(0,len(artifact_nodes)-1),"related_identities":len(identity_nodes)}
        suspicious = len(artifact_nodes) > 1 and len(identity_nodes) > 1
        return [EvidenceResult(self.name,"identity_graph_cluster" if suspicious else "artifact_graph",DetectorStatus.DETECTED if suspicious else DetectorStatus.NOT_DETECTED,value=context.metadata["graph"],reliability=.8,confidence=.8 if suspicious else .65,severity=20 if suspicious else 0,dependencies=["identity_graph"],details={"reason":"Persisted artifact and normalized-field relationships"})]
