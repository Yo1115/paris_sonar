import { Link, NavLink } from "react-router-dom";
import type { ReactNode } from "react";

interface LayoutProps {
  children: ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  return (
    <div className="app">
      <header className="hero">
        <div className="hero-overlay" />
        <div className="hero-content">
          <div className="brand">
            <Link to="/" className="logo">
              Paris Moments
            </Link>
            <p className="tagline">為你的品牌打造最浪漫的巴黎故事</p>
          </div>
          <nav className="nav">
            <NavLink to="/" end className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              首頁
            </NavLink>
            <NavLink to="/louvre" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              羅浮宮
            </NavLink>
            <NavLink to="/eiffel" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              艾菲爾鐵塔
            </NavLink>
            <NavLink to="/seine" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
              塞納河體驗
            </NavLink>
          </nav>
        </div>
      </header>
      <main className="main">{children}</main>
      <footer className="footer">
        <span>© {new Date().getFullYear()} Paris Moments Studio</span>
        <span>專注品牌體驗 · 內容行銷 · 目的地企劃</span>
      </footer>
    </div>
  );
};
