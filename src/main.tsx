import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import 'vis-timeline/styles/vis-timeline-graph2d.css'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
