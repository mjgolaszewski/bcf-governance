"""Build projection unit fixtures through the real compiler-owned option decoder."""
from types import SimpleNamespace
from bcf_governance.tooling.ci_graph_compile_options import _compile_render_options


def compiled_fixture(**values):
    graph = values.get("graph")
    if graph is None:
        graph = {"commands": values.get("commands", {}), "step_components": {}, "workflows": []}
    # Partial unit fixtures intentionally omit unrelated graph fields. Their
    # stable names are fixture data, never a production rendering fallback.
    graph.setdefault("commands", values.get("commands", {}))
    graph.setdefault("step_components", {})
    graph.setdefault("workflows", [])
    for index, workflow in enumerate(graph["workflows"]):
        workflow.setdefault("id", f"fixture-workflow-{index}")
        for position, job in enumerate(workflow["jobs"]):
            job.setdefault("id", f"fixture-job-{position}")
    modes, components, jobs = _compile_render_options(graph)
    return SimpleNamespace(**values, command_render_modes=modes,
                           component_render_options=components, job_render_options=jobs)
