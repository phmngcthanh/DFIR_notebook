declare module 'react-cytoscapejs' {
  import cytoscape from 'cytoscape';
  import * as React from 'react';

  interface CytoscapeComponentProps {
    elements?: cytoscape.ElementDefinition[];
    style?: React.CSSProperties;
    stylesheet?: cytoscape.StylesheetJson;
    layout?: cytoscape.LayoutOptions;
    cy?: (instance: cytoscape.Core) => void;
    minZoom?: number;
    maxZoom?: number;
    wheelSensitivity?: number;
    className?: string;
  }

  export default class CytoscapeComponent extends React.Component<CytoscapeComponentProps> {}
}

declare module 'cytoscape-dagre' {
  import cytoscape from 'cytoscape';
  const dagre: cytoscape.Ext;
  export default dagre;
}
