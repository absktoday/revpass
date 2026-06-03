<script lang="ts">
  import { Button } from "$lib/components/ui/button";
  import { invoke } from "@tauri-apps/api/core";

  let name = $state("");
  let greetMsg = $state("");

  async function greet(event: Event) {
    event.preventDefault();
    if (!name.trim()) return;
    // Call Tauri command
    greetMsg = await invoke("greet", { name: name.trim() });
  }
</script>

<main>
  Hello World

  <div class="flex flex-wrap items-center gap-2 md:flex-row">
    <Button>Button</Button>
  </div>
</main>
