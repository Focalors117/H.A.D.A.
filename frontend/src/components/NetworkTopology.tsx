import { useEffect, useMemo, useRef, useState } from 'react';
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
    graphRef.current?.zoom(1, 0);
    graphRef.current?.centerAt(0, 0, 0);
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
            const color =
              graphNode.type === 'router'
                ? '#f59e0b'
                : graphNode.status === 'Compromised'
                ? '#fb7185'
                : graphNode.status === 'Down'
                ? '#94a3b8'
                : '#34d399';

            ctx.beginPath();
            ctx.arc(
              node.x ?? 0,
              node.y ?? 0,
              graphNode.type === 'router' ? 8 : 6,
              0,
              2 * Math.PI,
              false
            );
            ctx.fillStyle = color;
            ctx.fill();

            ctx.font = `${fontSize}px Space Grotesk`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = '#cbd5e1';
            ctx.fillText(graphNode.label, node.x ?? 0, (node.y ?? 0) + 8);
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
