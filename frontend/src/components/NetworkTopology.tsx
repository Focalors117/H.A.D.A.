import { useEffect, useMemo, useRef, useState } from 'react';
import { forceCollide, forceLink, forceManyBody } from 'd3-force';
import ForceGraph2D, {
  type ForceGraphMethods,
  type LinkObject,
  type NodeObject,
} from 'react-force-graph-2d';

export interface TopologyNode {
  id: string;
  label: string;
  type: 'router' | 'device';
  status?: 'Active' | 'Down' | 'Compromised';
}

export interface TopologyLink {
  source: string;
  target: string;
}

export default function NetworkTopology({
  nodes,
  links,
  panEnabled = true,
}: {
  nodes: TopologyNode[];
  links: TopologyLink[];
  panEnabled?: boolean;
}) {
  const graphRef = useRef<
    ForceGraphMethods<NodeObject<TopologyNode>, LinkObject<TopologyNode, TopologyLink>> | undefined
  >(undefined);
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null);

  const hoveredDetails = useMemo(() => {
    if (!hoveredNode) return null;
    return hoveredNode.type === 'router'
      ? { title: hoveredNode.label, subtitle: 'Router central del workspace' }
      : {
          title: hoveredNode.label,
          subtitle: hoveredNode.status ? `Estado: ${hoveredNode.status}` : 'Activo conectado',
        };
  }, [hoveredNode]);

  useEffect(() => {
    const graph = graphRef.current as
      | (ForceGraphMethods<NodeObject<TopologyNode>, LinkObject<TopologyNode, TopologyLink>> & {
          d3Force?: (forceName: string, forceValue?: unknown) => unknown;
        })
      | undefined;

    if (!graph) return;

    const charge = graph.d3Force?.('charge') as ReturnType<typeof forceManyBody> | null;
    const link = graph.d3Force?.('link') as ReturnType<typeof forceLink> | null;
    const collide = graph.d3Force?.('collide') as ReturnType<typeof forceCollide> | null;

    charge?.strength(-400);
    link?.distance(120);
    collide?.radius(45);

    if (!collide) {
      graph.d3Force?.('collide', forceCollide(45));
    }

    graph.zoom(1, 0);
    graph.centerAt(0, 0, 0);
  }, [nodes, links]);

  return (
    <>
      <div className="topology-wrap">
        <ForceGraph2D
          ref={graphRef}
          graphData={{ nodes, links }}
          width={760}
          height={320}
          backgroundColor="rgba(2,6,23,0)"
          cooldownTicks={200}
          nodeRelSize={8}
          minZoom={0.85}
          maxZoom={1.75}
          enablePanInteraction={panEnabled}
          d3VelocityDecay={0.3}
          onNodeClick={(node) => {
            graphRef.current?.centerAt(node.x ?? 0, node.y ?? 0, 400);
            graphRef.current?.zoom(1.2, 400);
          }}
          onNodeHover={(node) => setHoveredNode((node as TopologyNode) ?? null)}
          nodeLabel={(node) =>
            `${String(node.label)} (${String((node as TopologyNode).status ?? 'N/A')})`
          }
          linkColor={() => 'rgba(148,163,184,0.38)'}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const graphNode = node as TopologyNode;
            const fontSize = Math.max(8, 12 / globalScale);
            const label = graphNode.label || graphNode.id;
            const color =
              graphNode.type === 'router'
                ? '#f59e0b'
                : graphNode.status === 'Compromised'
                ? '#fb7185'
                : graphNode.status === 'Down'
                ? '#94a3b8'
                : '#34d399';
            const radius = graphNode.type === 'router' ? 8 : 6;

            ctx.beginPath();
            ctx.arc(node.x ?? 0, node.y ?? 0, radius, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();

            ctx.strokeStyle = 'rgba(15,23,42,0.9)';
            ctx.lineWidth = Math.max(1, 1 / globalScale);
            ctx.stroke();

            ctx.font = `${fontSize}px Space Grotesk`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = '#e2e8f0';
            ctx.fillText(label, node.x ?? 0, (node.y ?? 0) + 14);
          }}
        />
      </div>
      {hoveredDetails && (
        <div className="topology-tooltip" aria-live="polite">
          <strong>{hoveredDetails.title}</strong>
          <span>{hoveredDetails.subtitle}</span>
        </div>
      )}
    </>
  );
}
