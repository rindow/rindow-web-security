<?php $this->placeholder()->set('title','Login Sample') ?>
<div class="container grid-container mdl-layout__content">
<div class="row grid-x mdl-grid">
<div class="col-sm-12 columns cell small-12 mdl-cell mdl-cell--12-col">
<?php if(isset($backurl)): ?><p>
  <nav>
    <a class="button tiny radius btn btn-sm btn-default" href="<?= $this->escape($backurl) ?>">&laquo; Back</a>
  </nav>
<?php endif ?></p>
<h3>Sign in</h3>
<?php $this->form()->addElement($form,'submit','go','Login',' ') ?>
<?= $this->form()->raw($form) ?>
</div>
</div>
</div><!--class="container"-->
