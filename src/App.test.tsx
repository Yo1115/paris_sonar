import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";

const renderWithRoute = (initialPath: string = "/") => {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <App />
    </MemoryRouter>
  );
};

describe("App", () => {
  it("renders homepage hero tagline", () => {
    renderWithRoute("/");

    expect(
      screen.getByText("為你的品牌打造最浪漫的巴黎故事")
    ).toBeInTheDocument();
  });

  it("shows navigation links and footer", () => {
    renderWithRoute("/");

    expect(screen.getByText("首頁")).toBeInTheDocument();
    expect(screen.getByText("羅浮宮")).toBeInTheDocument();
    expect(screen.getByText("艾菲爾鐵塔")).toBeInTheDocument();
    expect(screen.getByText("塞納河體驗")).toBeInTheDocument();
    expect(screen.getByText("蒙馬特")).toBeInTheDocument();

    expect(
      screen.getByText(/Paris Moments Studio/)
    ).toBeInTheDocument();
  });

  it("renders Louvre page on /louvre route", () => {
    renderWithRoute("/louvre");

    expect(
      screen.getByText("羅浮宮 · 藝術級品牌敘事")
    ).toBeInTheDocument();
  });

  it("renders Eiffel page on /eiffel route", () => {
    renderWithRoute("/eiffel");

    expect(
      screen.getByText("艾菲爾鐵塔 · 夜色中的品牌舞台")
    ).toBeInTheDocument();
  });

  it("renders Seine page on /seine route", () => {
    renderWithRoute("/seine");

    expect(
      screen.getByText("塞納河 · 流動中的內容行銷")
    ).toBeInTheDocument();
  });

  it("renders Montmartre page on /montmartre route", () => {
    renderWithRoute("/montmartre");

    expect(
      screen.getByText("蒙馬特 · 街區故事與品牌個性")
    ).toBeInTheDocument();
  });

  it("navigates between pages via nav links", async () => {
    const user = userEvent.setup();
    renderWithRoute("/");

    await user.click(screen.getByRole("link", { name: "羅浮宮" }));
    expect(
      screen.getByText("羅浮宮 · 藝術級品牌敘事")
    ).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "艾菲爾鐵塔" }));
    expect(
      screen.getByText("艾菲爾鐵塔 · 夜色中的品牌舞台")
    ).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "塞納河體驗" }));
    expect(
      screen.getByText("塞納河 · 流動中的內容行銷")
    ).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "蒙馬特" }));
    expect(
      screen.getByText("蒙馬特 · 街區故事與品牌個性")
    ).toBeInTheDocument();
  });
});

