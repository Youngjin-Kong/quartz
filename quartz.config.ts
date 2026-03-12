import { QuartzConfig } from "./quartz/cfg"
import * as Plugin from "./quartz/plugins"

/**
 * Quartz 4 Configuration
 *
 * See https://quartz.jzhao.xyz/configuration for more information.
 */
const config: QuartzConfig = {
  configuration: {
    // 1. 브라우저 탭에 표시될 이름입니다. 정하신 헤드라인과 맞췄습니다.
    pageTitle: "Offensive Security & Governance",
    pageTitleSuffix: " | Youngjin Kong",
    enableSPA: true,
    enablePopovers: true,
    analytics: {
      provider: "plausible",
    },
    // 2. 한국어 환경에 맞게 변경합니다.
    locale: "ko-KR", 
    // 3. GitHub Pages는 가급적 소문자 주소를 사용하는 것이 안전합니다.
    baseUrl: "youngjin-kong.github.io/quartz", 
    ignorePatterns: ["private", "templates", ".obsidian"],
    defaultDateType: "modified",
    theme: {
      fontOrigin: "googleFonts",
      cdnCaching: true,
      typography: {
        header: "Schibsted Grotesk",
        body: "Source Sans Pro",
        code: "IBM Plex Mono",
      },
	colors: {
	  lightMode: {
		light: "#ffffff",          // 메인 배경 (순백색)
		lightgray: "#f4f4f5",      // 검색창 및 경계선
		gray: "#adadad",           // 보조 텍스트 및 날짜
		darkgray: "#27272a",       // 메인 본문 텍스트 (가독성 높은 진한 회색)
		dark: "#09090b",           // 헤드라인 및 강조 텍스트
		secondary: "#18181b",      // 링크 및 카테고리 (차분한 블랙 계열)
		tertiary: "#71717a",       // 호버 상태 및 보조 링크
		highlight: "rgba(39, 39, 42, 0.05)", // 텍스트 하이라이트 배경
		textHighlight: "#fff23688", // 텍스트 형광펜 효과
	  },
	  darkMode: {
		// 다크 모드도 화이트 톤에 맞춰 대비를 조정하거나, 
		// 아예 위와 동일하게 설정하여 화이트 테마를 강제할 수 있습니다.
		light: "#ffffff",
		lightgray: "#f4f4f5",
		gray: "#adadad",
		darkgray: "#27272a",
		dark: "#09090b",
		secondary: "#18181b",
		tertiary: "#71717a",
		highlight: "rgba(39, 39, 42, 0.05)",
		textHighlight: "#fff23688",
	  },
	},
    },
  },
  plugins: {
    transformers: [
      Plugin.FrontMatter(),
      Plugin.CreatedModifiedDate({
        priority: ["frontmatter", "git", "filesystem"],
      }),
      Plugin.SyntaxHighlighting({
        theme: {
          light: "github-light",
          dark: "github-dark",
        },
        keepBackground: false,
      }),
      Plugin.ObsidianFlavoredMarkdown({ enableInHtmlEmbed: false }),
      Plugin.GitHubFlavoredMarkdown(),
      Plugin.TableOfContents(),
      Plugin.CrawlLinks({ markdownLinkResolution: "shortest" }),
      Plugin.Description(),
      Plugin.Latex({ renderEngine: "katex" }),
    ],
    filters: [Plugin.RemoveDrafts()],
    emitters: [
      Plugin.AliasRedirects(),
      Plugin.ComponentResources(),
      Plugin.ContentPage(),
      Plugin.FolderPage(),
      Plugin.TagPage(),
      Plugin.ContentIndex({
        enableSiteMap: true,
        enableRSS: true,
      }),
      Plugin.Assets(),
      Plugin.Static(),
      Plugin.Favicon(),
      Plugin.NotFoundPage(),
      // 빌드 속도를 위해 커스텀 OG 이미지는 선택사항입니다.
      Plugin.CustomOgImages(),
    ],
  },
}

export default config