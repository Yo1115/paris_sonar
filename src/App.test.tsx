import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";

describe("App", () => {
  it("renders homepage hero tagline", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    );

    expect(
      screen.getByText("為你的品牌打造最浪漫的巴黎故事")
    ).toBeInTheDocument();
  });

  it("shows navigation links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText("首頁")).toBeInTheDocument();
    expect(screen.getByText("羅浮宮")).toBeInTheDocument();
    expect(screen.getByText("艾菲爾鐵塔")).toBeInTheDocument();
    expect(screen.getByText("塞納河體驗")).toBeInTheDocument();
  });
});

