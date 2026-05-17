import NetworkTopology from './NetworkTopology';
import TopologyLegend from './TopologyLegend';
import type { FC } from 'react';
import type { TopologyNode, TopologyLink } from './NetworkTopology';

const TopologyPanel: FC<{ nodes: TopologyNode[]; links: TopologyLink[]; panEnabled?: boolean }> = ({
  nodes,
  links,
  panEnabled = true,
}) => {
  return (
    <>
      <div className="panel-divider" />
      <div className="panel-header">
        <div>
          <h2>Topología de red</h2>
          <p>Visualización viva del router central y activos conectados en esta red/workspace.</p>
        </div>
      </div>
      <NetworkTopology nodes={nodes} links={links} panEnabled={panEnabled} />
      <div className="panel-footer mt-4">
        <TopologyLegend />
      </div>
    </>
  );
};

export default TopologyPanel;
